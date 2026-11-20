// Actual private H2Mux factory and peer; memory only, no copied flow algorithm.
use super::*;

const CAPTURE_BYTES: usize = 4096;
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Default)]
pub(super) struct Wire {
    bytes: Vec<u8>,
    overflow: bool,
}
impl Wire {
    fn record(&mut self, bytes: &[u8]) {
        let count = bytes.len().min(CAPTURE_BYTES - self.bytes.len());
        self.overflow |= count != bytes.len();
        self.bytes.extend_from_slice(&bytes[..count]);
    }

    // Observe accepted protocol bytes, not a shadow flow-control state.
    fn initial_credit(&self) -> Result<(Vec<u32>, Vec<u32>), &'static str> {
        if self.overflow || !self.bytes.starts_with(PREFACE) {
            return Err("bounded client preface unavailable");
        }
        let mut settings = Vec::new();
        let mut connection = Vec::new();
        let mut offset = PREFACE.len();
        while offset < self.bytes.len() {
            let head = self.bytes.get(offset..offset + 9).ok_or("partial frame head")?;
            let length = (usize::from(head[0]) << 16)
                | (usize::from(head[1]) << 8)
                | usize::from(head[2]);
            let kind = head[3];
            let flags = head[4];
            let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]])
                & 0x7fff_ffff;
            offset += 9;
            let payload = self.bytes.get(offset..offset + length).ok_or("partial frame")?;
            if kind == 4 && flags & 1 == 0 {
                if stream != 0 || length % 6 != 0 {
                    return Err("invalid actual SETTINGS");
                }
                for value in payload.chunks_exact(6) {
                    if u16::from_be_bytes([value[0], value[1]]) == 4 {
                        settings.push(u32::from_be_bytes([value[2], value[3], value[4], value[5]]));
                    }
                }
            }
            if kind == 8 && stream == 0 {
                if payload.len() != 4 {
                    return Err("invalid actual connection WINDOW_UPDATE");
                }
                connection.push(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                    & 0x7fff_ffff);
            }
            offset += length;
        }
        Ok((settings, connection))
    }
}

pub(super) struct ObservedIo {
    pub(super) inner: DuplexStream,
    pub(super) wire: Arc<Mutex<Wire>>,
}
impl AsyncRead for ObservedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}
impl AsyncWrite for ObservedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, input);
        if let Poll::Ready(Ok(count)) = &result {
            self.wire.lock().unwrap().record(&input[..*count]);
        }
        result
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, input);
        if let Poll::Ready(Ok(count)) = &result {
            let mut remaining = *count;
            let mut wire = self.wire.lock().unwrap();
            for part in input {
                let count = part.len().min(remaining);
                wire.record(&part[..count]);
                remaining -= count;
                if remaining == 0 {
                    break;
                }
            }
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn initial_receive_credit_matches_settings_and_admits_bounded_entities() {
    tokio::task::unconstrained(async {
        // The +1024 case is opaque carrier data at a TLS-sized boundary, not
        // a claim that this harness executes TLS or an HTTP rewrite engine.
        for length in [32768, 65536, 65536 + 1024, 131072] {
            let mut fixture = OrdinaryFixture::open(false).await;
            let initial = fixture.wire.lock().unwrap().initial_credit();
            fixture.outputs[0].as_mut().unwrap()
                .send_data(Bytes::from(vec![1; length]), false).unwrap();
            fixture.outputs[TCP].as_mut().unwrap()
                .send_data(Bytes::from_static(b"u"), false).unwrap();
            for _ in 0..512 {
                fixture.drive();
                fixture.collect();
                if fixture.tcp[0] == length && fixture.sibling == b"u" {
                    break;
                }
            }
            let before_release = fixture.tcp;
            let sibling = fixture.sibling.clone();
            let active = !fixture.driver_done && !fixture.peer_done;
            let (joined, final_tcp, contents_ok, final_sibling) = fixture.finish();
            // Real credit release, both EOF directions and both protocol
            // owners precede every observation assertion, including old red.
            assert!(joined, "real H2 protocol owners did not naturally finish");
            let (settings, connection) = initial.expect("accepted initial H2 wire");
            assert_eq!(settings, [131072], "actual SETTINGS_INITIAL_WINDOW_SIZE");
            assert_eq!(connection, [1048576 - 65535], "original connection increment");
            assert!(active && contents_ok);
            assert_eq!(before_release[0], length, "stream stalled before real release");
            assert!(before_release[1..].iter().all(|count| *count == 0));
            assert_eq!(final_tcp, before_release);
            assert_eq!(sibling, b"u");
            assert_eq!(final_sibling, b"u");
        }
    }).await;
}

async fn hold_and_release_receive_credit<const STREAMS: usize, const TCP: usize>(
    h3_packet_up: bool,
    sibling_before_release: bool,
) {
    tokio::task::unconstrained(async {
        let mut fixture = Fixture::<STREAMS, TCP>::open(h3_packet_up).await;
        let initial = fixture.wire.lock().unwrap().initial_credit();
        for index in 0..TCP {
            fixture.outputs[index].as_mut().unwrap()
                .send_data(Bytes::from(vec![(index + 1) as u8; 131072]), false).unwrap();
        }
        for _ in 0..1024 {
            fixture.drive();
            fixture.collect();
            if fixture.tcp == [131072; TCP] {
                break;
            }
        }
        let held_tcp = fixture.tcp;
        fixture.sibling_pending_polls = 0;
        fixture.outputs[TCP].as_mut().unwrap()
            .send_data(Bytes::from_static(b"u"), false).unwrap();
        for _ in 0..64 {
            fixture.drive();
            fixture.collect();
        }
        let before_release = fixture.sibling.clone();
        let pending = fixture.sibling_pending_polls;
        let active = !fixture.driver_done && !fixture.peer_done;
        // finish() returns the actual retained TCP credit before draining the
        // sibling. No fabricated grant, extra connection credit or timeout.
        let (joined, final_tcp, contents_ok, final_sibling) = fixture.finish();
        assert!(joined, "real H2 protocol owners did not naturally finish");
        let (settings, connection) = initial.expect("accepted initial H2 wire");
        assert_eq!(settings, [131072]);
        let expected_window = if h3_packet_up { 1572864 } else { 1048576 };
        assert_eq!(connection, [expected_window - 65535]);
        assert!(active && contents_ok);
        assert_eq!(held_tcp, [131072; TCP]);
        if sibling_before_release {
            assert_eq!(before_release, b"u", "sibling did not use remaining connection credit");
        } else {
            assert!(before_release.is_empty() && pending > 0,
                "sibling DATA exceeded the connection receive credit");
        }
        assert_eq!(final_tcp, held_tcp);
        assert_eq!(final_sibling, b"u", "actual credit release did not resume sibling");
    }).await;
}

#[tokio::test]
async fn held_receive_data_stays_bounded_by_the_connection_window() {
    hold_and_release_receive_credit::<9, 8>(false, false).await;
}

#[tokio::test]
async fn h3_packet_up_connection_credit_leaves_room_for_a_ninth_stream() {
    hold_and_release_receive_credit::<9, 8>(true, true).await;
}

#[tokio::test]
async fn h3_packet_up_connection_credit_blocks_after_twelve_full_streams() {
    hold_and_release_receive_credit::<13, 12>(true, false).await;
}
