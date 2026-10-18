//! Mihomo mKCP options. These are bytes, not v2ray JSON's MiB buffer fields.
use super::{Result, invalid};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MkcpHeader {
    #[default]
    None,
    Srtp,
    Utp,
    WechatVideo,
    Dtls,
    Wireguard,
}
impl MkcpHeader {
    pub(crate) fn size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Srtp | Self::Utp | Self::Wireguard => 4,
            Self::WechatVideo | Self::Dtls => 13,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct MkcpOptions {
    pub mtu: u16,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub write_buffer: usize,
    pub read_buffer: usize,
    pub seed: Arc<str>,
    pub header: MkcpHeader,
}
impl std::fmt::Debug for MkcpOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MkcpOptions")
            .field("mtu", &self.mtu)
            .field("tti", &self.tti)
            .field("header", &self.header)
            .field("encrypted", &!self.seed.is_empty())
            .finish_non_exhaustive()
    }
}
impl Default for MkcpOptions {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            congestion: false,
            write_buffer: 2 * 1024 * 1024,
            read_buffer: 2 * 1024 * 1024,
            seed: Arc::from(""),
            header: MkcpHeader::None,
        }
    }
}
impl MkcpOptions {
    pub(crate) fn overhead(&self) -> usize {
        self.header.size() + if self.seed.is_empty() { 6 } else { 28 }
    }
    pub(crate) fn peer_receive_limit(&self) -> u16 {
        // The reference subtracts the AEAD tag but not its nonce from MSS;
        // its minimum MSS is 576 even at MTU 576. Accept that bounded wire,
        // while our own transmit path counts every envelope byte in MTU.
        let reference_security = if self.seed.is_empty() { 6 } else { 16 };
        let mss = (usize::from(self.mtu) - self.header.size() - reference_security - 18).max(576);
        u16::try_from(mss + self.overhead() + 18).expect("bounded mKCP MTU")
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawMkcp {
    #[serde(default)]
    mtu: u32,
    #[serde(default)]
    tti: u32,
    #[serde(rename = "uplink-capacity", default)]
    uplink_capacity: u32,
    #[serde(rename = "downlink-capacity", default)]
    downlink_capacity: u32,
    #[serde(default)]
    congestion: bool,
    #[serde(rename = "write-buffer", default)]
    write_buffer: u32,
    #[serde(rename = "read-buffer", default)]
    read_buffer: u32,
    #[serde(default)]
    seed: String,
    #[serde(default)]
    header: String,
}
impl RawMkcp {
    pub(super) fn normalize(self) -> Result<MkcpOptions> {
        let value = |number, default| if number == 0 { default } else { number };
        let mtu = value(self.mtu, 1350);
        let tti = value(self.tti, 50);
        let read = value(self.read_buffer, 2 * 1024 * 1024) as usize;
        let write = value(self.write_buffer, 2 * 1024 * 1024) as usize;
        if !(576..=1460).contains(&mtu)
            || !(10..=100).contains(&tti)
            || read < mtu as usize * 8
            || write < mtu as usize * 8
            || read > 16 * 1024 * 1024
            || write > 16 * 1024 * 1024
            || self.seed.len() > 4096
            || self.seed.contains('\0')
        {
            return invalid("mKCP options exceed the supported packet, timing or buffer boundary");
        }
        let header = match self.header.to_ascii_lowercase().as_str() {
            "" | "none" | "noop" => MkcpHeader::None,
            "srtp" => MkcpHeader::Srtp,
            "utp" => MkcpHeader::Utp,
            "wechat-video" | "wechat" => MkcpHeader::WechatVideo,
            "dtls" => MkcpHeader::Dtls,
            "wireguard" => MkcpHeader::Wireguard,
            _ => return invalid("unknown mKCP packet header"),
        };
        Ok(MkcpOptions {
            mtu: mtu as u16,
            tti,
            uplink_capacity: value(self.uplink_capacity, 5),
            downlink_capacity: value(self.downlink_capacity, 20),
            congestion: self.congestion,
            read_buffer: read,
            write_buffer: write,
            seed: Arc::from(self.seed),
            header,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mkcp_fields_have_checked_units_and_envelope_budget() {
        for header in ["none", "srtp", "utp", "wechat-video", "dtls", "wireguard"] {
            let raw:RawMkcp=serde_json::from_value(serde_json::json!({"header":header,"mtu":1350,"tti":20,"uplink-capacity":7,"downlink-capacity":11,"read-buffer":65536,"write-buffer":131072,"seed":"secret"})).unwrap();
            let options = raw.normalize().unwrap();
            assert_eq!(options.tti, 20);
            assert_eq!(options.write_buffer, 131072);
            assert_eq!(options.peer_receive_limit(), 1362);
            assert!(!format!("{options:?}").contains("secret"));
        }
        for fields in [
            serde_json::json!({"mtu":575}),
            serde_json::json!({"tti":1}),
            serde_json::json!({"read-buffer":1}),
            serde_json::json!({"write-buffer":u32::MAX}),
            serde_json::json!({"header":"not-a-header"}),
        ] {
            assert!(
                serde_json::from_value::<RawMkcp>(fields)
                    .unwrap()
                    .normalize()
                    .is_err()
            );
        }
    }
}
