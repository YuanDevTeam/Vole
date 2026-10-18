//! kcptun's public options; resource caps remain local implementation policy.
use super::*;
use serde_yaml_ng::Value;

#[derive(Clone, PartialEq, Eq)]
pub struct KcptunConfig {
    pub key: String,
    pub crypt: String,
    pub connections: u8,
    pub autoexpire: u32,
    pub scavengettl: u32,
    pub mtu: u16,
    pub rate_limit: u32,
    pub send_window: u16,
    pub receive_window: u16,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub dscp: u8,
    pub no_comp: bool,
    pub ack_nodelay: bool,
    pub nodelay: bool,
    pub interval: u32,
    pub resend: u32,
    pub no_congestion: bool,
    pub socket_buffer: usize,
    pub smux_version: u8,
    pub smux_buffer: usize,
    pub frame_size: usize,
    pub stream_buffer: usize,
    pub keepalive: u32,
}
impl std::fmt::Debug for KcptunConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcptunConfig")
            .field("smux_version", &self.smux_version)
            .finish_non_exhaustive()
    }
}
impl KcptunConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.key.len() > 65535
            || !(1..=8).contains(&self.connections)
            || !(512..=1500).contains(&self.mtu)
            || !(1..=4096).contains(&self.send_window)
            || !(1..=4096).contains(&self.receive_window)
            || (self.data_shards == 0) != (self.parity_shards == 0)
            || usize::from(self.data_shards) + usize::from(self.parity_shards) > 256
            || self.dscp > 63
            || !(10..=5000).contains(&self.interval)
            || self.resend > 32
            || !(1..=2).contains(&self.smux_version)
            || self.socket_buffer > 16 * 1024 * 1024
            || self.smux_buffer == 0
            || self.smux_buffer > 8 * 1024 * 1024
            || self.stream_buffer == 0
            || self.stream_buffer > self.smux_buffer
            || !(1..=65535).contains(&self.frame_size)
            || self.keepalive == 0
            || self.keepalive > 3600
            || self.autoexpire > 7 * 24 * 3600
            || self.scavengettl > 7 * 24 * 3600
            || !matches!(
                self.crypt.as_str(),
                "null"
                    | "none"
                    | "tea"
                    | "xor"
                    | "aes"
                    | "aes-128"
                    | "aes-192"
                    | "blowfish"
                    | "twofish"
                    | "cast5"
                    | "3des"
                    | "xtea"
                    | "salsa20"
                    | "aes-128-gcm"
            )
        {
            return invalid("invalid kcptun resource or transport options");
        }
        Ok(())
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKcptun {
    #[serde(default)]
    key: String,
    #[serde(default)]
    crypt: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    conn: u8,
    #[serde(default)]
    autoexpire: u32,
    #[serde(default)]
    scavengettl: u32,
    #[serde(default)]
    mtu: u16,
    #[serde(default)]
    ratelimit: u32,
    #[serde(default)]
    sndwnd: u16,
    #[serde(default)]
    rcvwnd: u16,
    #[serde(default)]
    datashard: i16,
    #[serde(default)]
    parityshard: i16,
    #[serde(default)]
    dscp: u8,
    #[serde(default)]
    nocomp: bool,
    #[serde(default)]
    acknodelay: bool,
    #[serde(default)]
    nodelay: u8,
    #[serde(default)]
    interval: u32,
    #[serde(default)]
    resend: u32,
    #[serde(default)]
    nc: u8,
    #[serde(default)]
    sockbuf: usize,
    #[serde(default)]
    smuxver: u8,
    #[serde(default)]
    smuxbuf: usize,
    #[serde(default)]
    framesize: usize,
    #[serde(default)]
    streambuf: usize,
    #[serde(default)]
    keepalive: u32,
}
pub(super) fn normalize(value: Value) -> Result<KcptunConfig> {
    let raw: RawKcptun = serde_yaml_ng::from_value(value)
        .map_err(|_| VoleError::InvalidConfig("invalid kcptun options".into()))?;
    if raw.nodelay > 1 || raw.nc > 1 {
        return invalid("invalid kcptun delay or congestion option");
    }
    let default_u32 = |v, d| if v == 0 { d } else { v };
    let default_usize = |v, d| if v == 0 { d } else { v };
    let (nodelay, interval, resend, nc) = match raw.mode.as_str() {
        "normal" => (false, 40, 2, true),
        "" | "fast" => (false, 30, 2, true),
        "fast2" => (true, 20, 2, true),
        "fast3" => (true, 10, 2, true),
        "manual" => (
            raw.nodelay != 0,
            default_u32(raw.interval, 50),
            raw.resend,
            raw.nc != 0,
        ),
        _ => return invalid("invalid kcptun mode"),
    };
    if !(-1..=255).contains(&raw.datashard) || !(-1..=255).contains(&raw.parityshard) {
        return invalid("invalid kcptun FEC shard counts");
    }
    let fec = raw.datashard >= 0 && raw.parityshard >= 0;
    let config = KcptunConfig {
        key: if raw.key.is_empty() {
            "it's a secrect".into()
        } else {
            raw.key
        },
        crypt: if raw.crypt.is_empty() {
            "aes".into()
        } else {
            raw.crypt
        },
        connections: if raw.conn == 0 { 1 } else { raw.conn },
        autoexpire: raw.autoexpire,
        scavengettl: default_u32(raw.scavengettl, 600),
        mtu: if raw.mtu == 0 { 1350 } else { raw.mtu },
        rate_limit: raw.ratelimit,
        send_window: if raw.sndwnd == 0 { 128 } else { raw.sndwnd },
        receive_window: if raw.rcvwnd == 0 { 512 } else { raw.rcvwnd },
        data_shards: if !fec {
            0
        } else if raw.datashard == 0 {
            10
        } else {
            raw.datashard as u8
        },
        parity_shards: if !fec {
            0
        } else if raw.parityshard == 0 {
            3
        } else {
            raw.parityshard as u8
        },
        dscp: raw.dscp,
        no_comp: raw.nocomp,
        ack_nodelay: raw.acknodelay,
        nodelay,
        interval,
        resend,
        no_congestion: nc,
        socket_buffer: default_usize(raw.sockbuf, 4 * 1024 * 1024),
        smux_version: if raw.smuxver == 0 { 1 } else { raw.smuxver },
        smux_buffer: default_usize(raw.smuxbuf, 4 * 1024 * 1024),
        frame_size: default_usize(raw.framesize, 8192),
        stream_buffer: default_usize(raw.streambuf, 2 * 1024 * 1024),
        keepalive: default_u32(raw.keepalive, 10),
    };
    config.validate()?;
    Ok(config)
}
impl Default for KcptunConfig {
    fn default() -> Self {
        normalize(serde_yaml_ng::Value::Mapping(Default::default())).expect("valid kcptun defaults")
    }
}
