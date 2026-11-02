//! Bounded recognition of inner TLS records. It is a traffic classifier, not
//! a TLS authenticator; the inner endpoint still verifies its own handshake.
#[derive(Default)]
struct Records {
    header: [u8; 5],
    used: usize,
    remaining: usize,
    invalid: bool,
    hello: Vec<u8>,
    hello_done: bool,
}
#[derive(Default)]
pub(super) struct Filter {
    upload: Records,
    download: Records,
    tls: bool,
    direct: Option<bool>,
    frames: usize,
}
impl Filter {
    pub(super) fn received(&mut self, data: &[u8]) {
        self.download.feed(data, &mut self.tls, &mut self.direct);
    }
    pub(super) fn command(&mut self, data: &[u8]) -> u8 {
        self.frames = self.frames.saturating_add(1);
        let application = self.upload.feed(data, &mut self.tls, &mut self.direct);
        if self.tls && application {
            if self.direct == Some(true) { 2 } else { 1 }
        } else if !self.tls && self.frames >= 7 {
            1
        } else {
            0
        }
    }
    pub(super) fn is_tls(&self) -> bool {
        self.tls
    }
}
impl Records {
    fn feed(&mut self, mut data: &[u8], tls: &mut bool, direct: &mut Option<bool>) -> bool {
        let mut application = false;
        while !data.is_empty() && !self.invalid {
            if self.used < 5 {
                let count = (5 - self.used).min(data.len());
                self.header[self.used..self.used + count].copy_from_slice(&data[..count]);
                self.used += count;
                data = &data[count..];
                if self.used < 5 {
                    break;
                }
                self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                if !matches!(self.header[0], 20..=23)
                    || self.header[1] != 3
                    || self.header[2] > 3
                    || self.remaining > crate::limits::VISION_TLS_RECORD_BYTES
                {
                    self.invalid = true;
                    self.hello.clear();
                    break;
                }
                application |= self.header[0] == 23;
                if self.remaining == 0 {
                    self.used = 0;
                    continue;
                }
            }
            let count = self.remaining.min(data.len());
            application |= self.header[0] == 23 && count > 0;
            if count > 0 && self.header[0] == 22 && !self.hello_done {
                // Only the first hello is relevant. Excess handshake content
                // disables classification rather than allocating without bound.
                if self.hello.len() + count > crate::limits::VISION_HELLO_BYTES {
                    self.hello_done = true;
                    self.hello.clear();
                } else {
                    self.hello.extend_from_slice(&data[..count]);
                    if self.hello.first() == Some(&1) {
                        *tls = true;
                        self.hello_done = true;
                        self.hello.clear();
                    } else if self.hello.first() != Some(&2) {
                        self.hello_done = true;
                        self.hello.clear();
                    } else if self.hello.len() >= 4 {
                        let need = 4
                            + ((self.hello[1] as usize) << 16)
                            + ((self.hello[2] as usize) << 8)
                            + self.hello[3] as usize;
                        if need > crate::limits::VISION_HELLO_BYTES {
                            self.hello_done = true;
                            self.hello.clear();
                        } else if self.hello.len() >= need {
                            if let Some(version) = server_hello(&self.hello[..need]) {
                                *tls = true;
                                *direct = Some(version);
                            }
                            self.hello_done = true;
                            self.hello.clear();
                        }
                    }
                }
            }
            self.remaining -= count;
            data = &data[count..];
            if self.remaining == 0 {
                self.used = 0;
            }
        }
        application
    }
}
fn server_hello(hello: &[u8]) -> Option<bool> {
    if hello.len() < 42 || hello[4..6] != [3, 3] {
        return None;
    }
    let session = hello[38] as usize;
    if session > 32 {
        return None;
    }
    let mut pos = 39 + session;
    let cipher = u16::from_be_bytes(hello.get(pos..pos + 2)?.try_into().ok()?);
    pos += 3; // cipher + compression
    if pos == hello.len() {
        return Some(false);
    }
    let length = u16::from_be_bytes(hello.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos += 2;
    if pos + length != hello.len() {
        return None;
    }
    let mut tls13 = false;
    while pos < hello.len() {
        let kind = u16::from_be_bytes(hello.get(pos..pos + 2)?.try_into().ok()?);
        let length = u16::from_be_bytes(hello.get(pos + 2..pos + 4)?.try_into().ok()?) as usize;
        let content = hello.get(pos + 4..pos + 4 + length)?;
        if kind == 43 {
            tls13 = content == [3, 4];
        }
        pos += 4 + length;
    }
    Some(tls13 && matches!(cipher, 0x1301..=0x1304))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello(tls13: bool) -> Vec<u8> {
        let mut body = vec![2, 0, 0, 0, 3, 3];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0x13, 1, 0, 0, if tls13 { 6 } else { 0 }]);
        if tls13 {
            body.extend_from_slice(&[0, 43, 0, 2, 3, 4]);
        }
        let length = body.len() - 4;
        body[3] = length as u8;
        let mut record = vec![22, 3, 3, 0, body.len() as u8];
        record.extend_from_slice(&body);
        record
    }
    #[test]
    fn fragmented_server_hello_distinguishes_tls12_tls13_and_non_tls() {
        for tls13 in [false, true] {
            for chunk in [1, 3, 8192] {
                let mut filter = Filter::default();
                for part in hello(tls13).chunks(chunk) {
                    filter.received(part);
                }
                assert_eq!(
                    filter.command(&[23, 3, 3, 0, 1, 42]),
                    if tls13 { 2 } else { 1 }
                );
            }
        }
        let mut filter = Filter::default();
        for _ in 0..6 {
            assert_eq!(filter.command(b"not TLS"), 0);
        }
        assert_eq!(filter.command(b"not TLS"), 1);
        let mut filter = Filter::default();
        filter.received(&[22, 3, 3, 255, 255]);
        assert_ne!(filter.command(&[23, 3, 3, 0, 1, 42]), 2);
    }
}
