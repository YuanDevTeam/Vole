//! VMess AEAD client over caller-owned IO. No socket creation, resolver, legacy
//! authentication, or peer-controlled cipher negotiation lives in this module.
//! Wire references: v2fly/v2ray-core proxy/vmess/encoding and Clash-RS vmess_impl.
mod crypto;
mod datagram;
mod outbound;
pub use outbound::VmessOutbound;
mod header;
mod stream;
pub use datagram::VmessDatagram;
pub use header::{ClientHandshake, Command, VmessIdentity};
pub use stream::{MAX_BODY_WIRE, MAX_PACKET_BYTES, VmessStream, WRITE_CHUNK};

use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyCipher {
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

impl BodyCipher {
    pub fn resolved(self) -> Self {
        self.with_aes_hardware(aes::hardware_accelerated())
    }
    fn with_aes_hardware(self, accelerated: bool) -> Self {
        match self {
            Self::Auto if accelerated => Self::Aes128Gcm,
            Self::Auto => Self::Chacha20Poly1305,
            other => other,
        }
    }
    fn wire(self) -> u8 {
        match self.resolved() {
            Self::Aes128Gcm => 3,
            Self::Chacha20Poly1305 => 4,
            Self::None => 5,
            Self::Auto => unreachable!("auto resolved"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BodyOptions {
    cipher: BodyCipher,
    padding: bool,
    authenticated_length: bool,
}

impl BodyOptions {
    pub fn new(cipher: BodyCipher, padding: bool, authenticated_length: bool) -> io::Result<Self> {
        if cipher == BodyCipher::None && (padding || authenticated_length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess none cannot enable padding or authenticated length",
            ));
        }
        Ok(Self {
            cipher: cipher.resolved(),
            padding,
            authenticated_length,
        })
    }
    fn wire(self, command: Command) -> u8 {
        if self.cipher == BodyCipher::None {
            return u8::from(command == Command::Udp);
        }
        1 | 4 | (u8::from(self.padding) << 3) | (u8::from(self.authenticated_length) << 4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auto_uses_detected_hardware_not_architecture_name() {
        assert_eq!(
            BodyCipher::Auto.with_aes_hardware(true),
            BodyCipher::Aes128Gcm
        );
        assert_eq!(
            BodyCipher::Auto.with_aes_hardware(false),
            BodyCipher::Chacha20Poly1305
        );
    }
}
