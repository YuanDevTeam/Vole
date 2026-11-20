//! Actual production h2mux receive credit over a bounded memory carrier.
//! TCP/UDP names describe consumer roles; this is not a datagram-codec test.
use super::*;
use bytes::Bytes;
use futures_util::task::noop_waker;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

const TCP: usize = 8;
const STREAMS: usize = TCP + 1;
const STREAM_BYTES: usize = 65536;

type Requester = h2::client::SendRequest<crate::transport::h2_write::Payload>;
type OrdinaryFixture = Fixture<STREAMS, TCP>;

struct Fixture<const STREAMS: usize, const TCP: usize> {
    wire: Arc<Mutex<initial_window_contract::Wire>>,
    driver: Pin<Box<dyn Future<Output = ()> + Send>>,
    peer: h2::server::Connection<DuplexStream, Bytes>,
    sender: Option<Requester>,
    responses: [Option<h2::client::ResponseFuture>; STREAMS],
    bodies: [Option<h2::RecvStream>; STREAMS],
    inputs: [Option<h2::RecvStream>; STREAMS],
    outputs: [Option<h2::SendStream<Bytes>>; STREAMS],
    tcp: [usize; TCP],
    sibling: Vec<u8>,
    sibling_pending_polls: usize,
    held: Vec<Bytes>,
    body_eof: [bool; STREAMS],
    input_eof: [bool; STREAMS],
    accepted: usize,
    contents_ok: bool,
    driver_done: bool,
    peer_done: bool,
}
impl<const STREAMS: usize, const TCP: usize> Fixture<STREAMS, TCP> {
    async fn open(h3_packet_up: bool) -> Self {
        assert_eq!(STREAMS, TCP + 1);
        let (client, peer) = tokio::io::duplex(65536);
        let wire = Arc::new(Mutex::new(initial_window_contract::Wire::default()));
        let (client, peer) = tokio::join!(
            new(
                Box::new(initial_window_contract::ObservedIo {
                    inner: client,
                    wire: wire.clone(),
                }),
                h3_packet_up,
            ),
            h2::server::Builder::new().handshake::<_, Bytes>(peer),
        );
        let (sender, driver) = client.unwrap();
        let mut fixture = Self {
            wire,
            driver: Box::pin(driver),
            peer: peer.unwrap(),
            sender: Some(sender.request),
            responses: std::array::from_fn(|_| None),
            bodies: std::array::from_fn(|_| None),
            inputs: std::array::from_fn(|_| None),
            outputs: std::array::from_fn(|_| None),
            tcp: [0; TCP],
            sibling: Vec::new(),
            sibling_pending_polls: 0,
            held: Vec::new(),
            body_eof: [false; STREAMS],
            input_eof: [false; STREAMS],
            accepted: 0,
            contents_ok: true,
            driver_done: false,
            peer_done: false,
        };
        for index in 0..STREAMS {
            for _ in 0..128 {
                let waker = noop_waker();
                let mut cx = Context::from_waker(&waker);
                if let Poll::Ready(result) = fixture.sender.as_mut().unwrap().poll_ready(&mut cx) {
                    result.unwrap();
                    let request = http::Request::builder()
                        .method("CONNECT")
                        .uri("https://localhost")
                        .body(())
                        .unwrap();
                    let (response, _) = fixture
                        .sender
                        .as_mut()
                        .unwrap()
                        .send_request(request, true)
                        .unwrap();
                    fixture.responses[index] = Some(response);
                    break;
                }
                fixture.drive();
            }
            assert!(
                fixture.responses[index].is_some(),
                "real CONNECT admission stalled"
            );
        }
        for _ in 0..128 {
            fixture.drive();
            if fixture.accepted == STREAMS && fixture.bodies.iter().all(Option::is_some) {
                for _ in 0..8 {
                    fixture.drive();
                }
                return fixture;
            }
        }
        panic!("real H2 response setup did not complete");
    }
    fn drive(&mut self) {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        if !self.driver_done {
            self.driver_done = self.driver.as_mut().poll(&mut cx).is_ready();
        }
        if !self.peer_done {
            match self.peer.poll_accept(&mut cx) {
                Poll::Ready(Some(Ok((request, mut reply)))) => {
                    let index = self.accepted;
                    assert!(index < STREAMS && request.method() == "CONNECT");
                    self.inputs[index] = Some(request.into_body());
                    self.outputs[index] =
                        Some(reply.send_response(http::Response::new(()), false).unwrap());
                    self.accepted += 1;
                }
                Poll::Ready(Some(Err(error))) => panic!("real H2 peer failed: {error}"),
                Poll::Ready(None) => self.peer_done = true,
                Poll::Pending => {}
            }
        }
        for index in 0..STREAMS {
            if let Some(response) = &mut self.responses[index] {
                if let Poll::Ready(result) = Pin::new(response).poll(&mut cx) {
                    self.bodies[index] = Some(result.unwrap().into_body());
                    self.responses[index] = None;
                }
            }
        }
    }
    fn collect(&mut self) {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for index in 0..STREAMS {
            if let Some(body) = &mut self.bodies[index] {
                for _ in 0..8 {
                    match body.poll_data(&mut cx) {
                        Poll::Ready(Some(Ok(bytes))) => {
                            if index < TCP {
                                self.tcp[index] += bytes.len();
                                self.contents_ok &=
                                    bytes.iter().all(|byte| *byte == (index + 1) as u8);
                                // Keep the real payload and do not release its credit.
                                self.held.push(bytes);
                            } else {
                                self.sibling.extend_from_slice(&bytes);
                            }
                        }
                        Poll::Ready(Some(Err(error))) => panic!("real H2 body failed: {error}"),
                        Poll::Ready(None) => {
                            self.body_eof[index] = true;
                            break;
                        }
                        Poll::Pending => {
                            if index == TCP {
                                self.sibling_pending_polls += 1;
                            }
                            break;
                        }
                    }
                }
            }
            if let Some(input) = &mut self.inputs[index] {
                match input.poll_data(&mut cx) {
                    Poll::Ready(None) => self.input_eof[index] = true,
                    Poll::Ready(Some(Ok(bytes))) => {
                        assert!(bytes.is_empty(), "unexpected request DATA")
                    }
                    Poll::Ready(Some(Err(error))) => panic!("request EOF failed: {error}"),
                    Poll::Pending => {}
                }
            }
        }
    }
    fn finish(mut self) -> (bool, [usize; TCP], bool, Vec<u8>) {
        // A blocked sibling must resume after true consumption.
        for index in 0..TCP {
            self.bodies[index]
                .as_mut()
                .unwrap()
                .flow_control()
                .release_capacity(self.tcp[index])
                .unwrap();
        }
        self.held.clear();
        for _ in 0..256 {
            self.drive();
            self.collect();
            if self.sibling.len() == 1 {
                break;
            }
        }
        self.bodies[TCP]
            .as_mut()
            .unwrap()
            .flow_control()
            .release_capacity(self.sibling.len())
            .unwrap();
        for output in self.outputs.iter_mut().flatten() {
            output.send_data(Bytes::new(), true).unwrap();
        }
        for _ in 0..256 {
            self.drive();
            self.collect();
            if self.body_eof.iter().all(|eof| *eof) && self.input_eof.iter().all(|eof| *eof) {
                break;
            }
        }
        let all_eof = self.body_eof.iter().all(|eof| *eof) && self.input_eof.iter().all(|eof| *eof);
        for index in 0..STREAMS {
            drop(self.responses[index].take());
            drop(self.bodies[index].take());
            drop(self.inputs[index].take());
            drop(self.outputs[index].take());
        }
        drop(self.sender.take());
        self.held.clear();
        for _ in 0..256 {
            self.drive();
            if self.driver_done && self.peer_done {
                break;
            }
        }
        (
            all_eof && self.driver_done && self.peer_done,
            self.tcp,
            self.contents_ok,
            self.sibling,
        )
    }
}

#[tokio::test]
async fn held_tcp_windows_leave_receive_credit_for_a_sibling() {
    tokio::task::unconstrained(async {
        let mut fixture = OrdinaryFixture::open(false).await;
        for index in 0..TCP {
            fixture.outputs[index]
                .as_mut()
                .unwrap()
                .send_data(Bytes::from(vec![(index + 1) as u8; STREAM_BYTES]), false)
                .unwrap();
        }
        for _ in 0..512 {
            fixture.drive();
            fixture.collect();
            if fixture.tcp == [STREAM_BYTES; TCP] {
                break;
            }
        }
        let held_tcp = fixture.tcp;
        fixture.sibling_pending_polls = 0;
        fixture.outputs[TCP]
            .as_mut()
            .unwrap()
            .send_data(Bytes::from_static(b"u"), false)
            .unwrap();
        for _ in 0..64 {
            fixture.drive();
            fixture.collect();
        }
        let before_release = fixture.sibling.clone();
        let pending_before_release = fixture.sibling_pending_polls;
        // An empty result records real recv Pending after the peer queued DATA;
        // no fake flow-control count or copied production window is involved.
        let active = !fixture.driver_done && !fixture.peer_done;
        let (joined, final_tcp, contents_ok, final_sibling) = fixture.finish();
        assert!(joined, "real H2 protocol owners did not naturally finish");
        assert!(active && contents_ok);
        assert!(!before_release.is_empty() || pending_before_release > 0);
        assert_eq!(
            held_tcp, [STREAM_BYTES; TCP],
            "the original 64KiB TCP entities were not actually retained"
        );
        assert_eq!(final_tcp, held_tcp);
        assert_eq!(
            final_sibling, b"u",
            "true TCP credit release did not resume the sibling"
        );
        // Expected old-code red is last, after real credit release and owner exit.
        assert_eq!(
            before_release, b"u",
            "held TCP stream windows exhausted sibling connection credit"
        );
    })
    .await;
}

#[forbid(unsafe_code)]
mod initial_window_contract {
    include!("h2_initial_receive_window_tests.rs");
}
