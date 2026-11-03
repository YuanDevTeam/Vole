//! Frame-aligned delivery and prefix budgets before the official H3 decoder.
//! DATA is skipped by length; payload slices share the native Quinn backing.
use h3::error::Code;

#[derive(Default)]
struct Varint {
    left: u8,
    value: u64,
    started: bool,
}

impl Varint {
    fn push(&mut self, byte: u8) -> Option<u64> {
        if self.started {
            self.value = (self.value << 8) | u64::from(byte);
            self.left -= 1;
        } else {
            self.started = true;
            self.left = (1 << (byte >> 6)) - 1;
            self.value = u64::from(byte & 63);
        }
        (self.left == 0).then_some(self.value)
    }
}

enum State {
    UniType(Varint),
    PushId(Varint),
    FrameType(Varint),
    FrameLength(Varint),
    Payload(u64),
    Bypass,
}

pub(super) struct Budget {
    state: State,
    frame_type: u64,
    header_wire: u64,
    control: bool,
}

impl Budget {
    pub(super) fn new(header_limit: u64, unidirectional: bool) -> Self {
        Self {
            state: if unidirectional {
                State::UniType(Varint::default())
            } else {
                State::FrameType(Varint::default())
            },
            frame_type: 0,
            header_wire: header_limit.saturating_add(header_limit / 2),
            control: false,
        }
    }

    pub(super) fn is_control(&self) -> bool {
        self.control
    }

    /// Separate a frame's header from its payload and the following frame.
    /// h3 0.0.8 polls for another chunk before consuming its buffered DATA.
    /// Returning coalesced frames would let that buffer grow outside Quinn's
    /// receive window even while the application is reading slowly.
    pub(super) fn prefix(&mut self, bytes: &[u8]) -> Result<usize, Code> {
        let mut offset = 0;
        while offset < bytes.len() {
            match &mut self.state {
                State::Bypass => return Ok(bytes.len()),
                State::Payload(left) => {
                    let n = (*left).min((bytes.len() - offset) as u64) as usize;
                    offset += n;
                    *left -= n as u64;
                    if *left == 0 {
                        self.state = State::FrameType(Varint::default());
                    }
                    return Ok(offset);
                }
                State::UniType(value) => {
                    let value = value.push(bytes[offset]);
                    offset += 1;
                    if let Some(value) = value {
                        self.control = value == 0;
                        self.state = match value {
                            0 => State::FrameType(Varint::default()),
                            1 => State::PushId(Varint::default()),
                            // QPACK is not H3 framing. The official backend
                            // retains its QPACK streams and aborts unknown uni.
                            _ => State::Bypass,
                        };
                        return Ok(offset);
                    }
                }
                State::PushId(value) => {
                    let value = value.push(bytes[offset]);
                    offset += 1;
                    if value.is_some() {
                        self.state = State::FrameType(Varint::default());
                        return Ok(offset);
                    }
                }
                State::FrameType(value) => {
                    let value = value.push(bytes[offset]);
                    offset += 1;
                    if let Some(value) = value {
                        self.frame_type = value;
                        if value == 0x41 {
                            // The official codec's WebTransport bidi marker
                            // has a session ID instead of a frame length.
                            self.state = State::Bypass;
                            return Ok(offset);
                        }
                        self.state = State::FrameLength(Varint::default());
                    }
                }
                State::FrameLength(value) => {
                    let value = value.push(bytes[offset]);
                    offset += 1;
                    if let Some(length) = value {
                        check_length(self.frame_type, length, self.header_wire)?;
                        self.state = if length == 0 {
                            State::FrameType(Varint::default())
                        } else {
                            State::Payload(length)
                        };
                        return Ok(offset);
                    }
                }
            }
        }
        Ok(offset)
    }

    #[cfg(test)]
    pub(super) fn check(&mut self, mut bytes: &[u8]) -> Result<(), Code> {
        while !bytes.is_empty() {
            let count = self.prefix(bytes)?;
            bytes = &bytes[count..];
        }
        Ok(())
    }
}

fn check_length(frame: u64, length: u64, header_wire: u64) -> Result<(), Code> {
    match frame {
        // The official decoder stores DATA's remaining length in usize.
        // Refuse a valid wire length that this target cannot represent rather
        // than letting its conversion truncate framing. This is a target
        // resource limit, not a DATA body cap: all QUIC lengths fit on 64-bit.
        0 => usize::try_from(length)
            .map(|_| ())
            .map_err(|_| Code::H3_EXCESSIVE_LOAD),
        1 if length <= header_wire => Ok(()),
        1 => Err(Code::H3_EXCESSIVE_LOAD),
        3 | 7 | 13 if (1..=8).contains(&length) => Ok(()),
        3 | 7 | 13 => Err(Code::H3_FRAME_ERROR),
        4 if length <= 256 => Ok(()),
        4 => Err(Code::H3_FRAME_ERROR),
        5 if length == 0 => Err(Code::H3_FRAME_ERROR),
        5 if length <= header_wire.saturating_add(8) => Ok(()),
        5 => Err(Code::H3_EXCESSIVE_LOAD),
        // The official codec buffers unknown frames before ignoring them.
        // Bound that buffering to the encoded-header budget instead of the
        // quiche backend's 16 MiB skip limit, which does not retain a payload.
        _ if length <= header_wire => Ok(()),
        _ => Err(Code::H3_EXCESSIVE_LOAD),
    }
}

#[cfg(all(test, target_pointer_width = "32"))]
mod tests {
    use super::*;

    #[test]
    fn data_length_overflow_is_rejected_at_prefix_without_body() {
        // Literal HTTP/3 DATA prefixes: 2^32-1 is representable; 2^32 is not.
        // No payload is allocated or consumed for either declaration.
        let mut valid = Budget::new(16 * 1024, false);
        assert!(
            valid
                .check(&[0, 0xc0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff])
                .is_ok()
        );
        let oversized = [0, 0xc0, 0, 0, 1, 0, 0, 0, 0];
        for split in 0..oversized.len() {
            let mut budget = Budget::new(16 * 1024, false);
            assert!(budget.check(&oversized[..split]).is_ok());
            assert_eq!(
                budget.check(&oversized[split..]),
                Err(Code::H3_EXCESSIVE_LOAD)
            );
        }
    }
}
