//! Independent low-order bit matcher, retaining the unmasked payload address.
use super::{Result, VoleError};
use std::{net::IpAddr, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSuffix {
    address: IpAddr,
    bits: u8,
    payload: Arc<str>,
}
impl IpSuffix {
    pub fn parse(payload: &str) -> Result<Self> {
        let invalid =
            || VoleError::InvalidConfig("IP-SUFFIX requires an address and valid bit width".into());
        let (address, bits) = payload.split_once('/').ok_or_else(invalid)?;
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        if bits.is_empty() || !bits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let bits: u8 = bits.parse().map_err(|_| invalid())?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if bits > maximum {
            return Err(invalid());
        }
        Ok(Self {
            address,
            bits,
            payload: Arc::from(payload),
        })
    }
    pub fn as_str(&self) -> &str {
        &self.payload
    }
    pub fn matches(&self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(expected), IpAddr::V4(candidate)) => {
                let mask = u32::MAX.checked_shr(32 - u32::from(self.bits)).unwrap_or(0);
                u32::from(expected) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(expected), IpAddr::V6(candidate)) => {
                let mask = u128::MAX
                    .checked_shr(128 - u32::from(self.bits))
                    .unwrap_or(0);
                u128::from(expected) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn address_suffix_preserves_low_bits_and_address_family() {
        for (payload, candidate) in [
            ("192.0.2.19/5", "203.0.113.51"),
            ("2001:db8::12ab/13", "fd01::32ab"),
            ("192.0.2.19/0", "203.0.113.1"),
            ("2001:db8::19/0", "::"),
            ("192.0.2.19/32", "192.0.2.19"),
            ("2001:db8::19/128", "2001:db8::19"),
        ] {
            let suffix = IpSuffix::parse(payload).unwrap();
            assert_eq!(suffix.as_str(), payload);
            assert!(suffix.matches(candidate.parse().unwrap()));
        }
        let suffix = IpSuffix::parse("192.0.2.19/5").unwrap();
        assert!(!suffix.matches("203.0.113.52".parse().unwrap()));
        assert!(!suffix.matches("::ffff:192.0.2.19".parse().unwrap()));
    }
}
