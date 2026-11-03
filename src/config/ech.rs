//! Bounded static or DNS-sourced ECH admission for the selected TLS backend.
//! Admission precedes handshake setup so no backend silently skips ECH.
use super::*;

#[derive(Clone)]
pub struct StaticEchConfig {
    wire: Vec<u8>,
    source: std::sync::Arc<[u8]>,
    query: Option<Option<String>>,
    named: bool,
}

impl PartialEq for StaticEchConfig {
    fn eq(&self, other: &Self) -> bool {
        self.wire == other.wire && self.query == other.query && self.named == other.named
    }
}
impl Eq for StaticEchConfig {}

impl std::fmt::Debug for StaticEchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticEchConfig").finish_non_exhaustive()
    }
}

impl StaticEchConfig {
    /// Keeps the first mutually supported config's exact wire encoding. No
    /// backend can skip an earlier unsupported entry and expose the inner SNI.
    pub fn from_config_list(bytes: &[u8]) -> Result<Self> {
        Self::from_config_list_for_backend(bytes, true)
    }

    pub(crate) fn from_config_list_for_backend(bytes: &[u8], named: bool) -> Result<Self> {
        if bytes.len() > 65_537 {
            return invalid("ECH config list exceeds the wire bound");
        }
        let mut reader = Reader(bytes);
        let list = reader.vector16()?;
        reader.end()?;
        let mut configs = Reader(list);
        let mut selected = None;
        while !configs.0.is_empty() {
            let start = configs.0;
            let version = configs.u16()?;
            let contents = configs.vector16()?;
            if version == 0xfe0d && supported(contents, named)? && selected.is_none() {
                selected = Some(&start[..4 + contents.len()]);
            }
        }
        let selected = selected.ok_or_else(|| {
            VoleError::InvalidConfig("ECH has no compatible configuration".into())
        })?;
        let mut wire = (selected.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(selected);
        Ok(Self {
            wire,
            source: bytes.into(),
            query: None,
            named,
        })
    }

    #[cfg(any(feature = "tls-fingerprint", feature = "ech"))]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        assert!(
            self.query.is_none(),
            "dynamic ECH must resolve before TLS setup"
        );
        &self.wire
    }
    pub(crate) fn for_backend(&self, named: bool) -> Result<Self> {
        if self.named == named {
            return Ok(self.clone());
        }
        if self.is_dynamic() {
            return Ok(Self {
                named,
                ..self.clone()
            });
        }
        Self::from_config_list_for_backend(&self.source, named)
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        self.query.is_some()
    }
    pub(crate) async fn resolve(
        &self,
        server_name: &str,
        context: &crate::outbound::EstablishContext,
    ) -> std::io::Result<Self> {
        let Some(query) = &self.query else {
            return Ok(self.clone());
        };
        let wire = context
            .resolution()
            .resolve_ech(query.as_deref().unwrap_or(server_name), context.deadline())
            .await?;
        Self::from_config_list_for_backend(&wire, self.named)
            .map_err(|_| std::io::Error::other("DNS has no compatible ECH configuration"))
    }
}

fn supported(bytes: &[u8], named: bool) -> Result<bool> {
    let mut r = Reader(bytes);
    r.take(1)?; // config_id
    let kem = r.u16()?;
    let key = r.vector16()?;
    let suites = r.vector16()?;
    if suites.is_empty() || !suites.len().is_multiple_of(4) {
        return invalid("invalid ECH cipher suites");
    }
    let compatible_suite = suites.as_chunks::<4>().0.iter().any(|suite| {
        matches!(u16::from_be_bytes([suite[2], suite[3]]), 1..=3)
            && if named {
                suite[..2] == [0, 1]
            } else {
                matches!(u16::from_be_bytes([suite[0],suite[1]]), 1..=3 | 0x10..=0x11)
            }
    });
    r.take(1)?; // maximum_name_length
    let name_len = usize::from(r.take(1)?[0]);
    let name = r.take(name_len)?;
    let mut extensions = Reader(r.vector16()?);
    r.end()?;
    let mut seen = std::collections::BTreeSet::new();
    let mut compatible_extensions = true;
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        extensions.vector16()?;
        compatible_extensions &= kind & 0x8000 == 0 && seen.insert(kind);
    }
    let compatible_key = if named {
        kem == 0x0020 && key.len() == 32
    } else {
        #[cfg(feature = "ech")]
        {
            crate::security::ech::valid_public_key(kem, key)
        }
        #[cfg(not(feature = "ech"))]
        {
            false
        }
    };
    Ok(compatible_key
        && compatible_suite
        && compatible_extensions
        && valid_public_name(name, named))
}

fn valid_public_name(name: &[u8], named: bool) -> bool {
    // The reference requires a multi-label LDH name. The selected backend
    // must also represent it; BoringSSL rejects hexadecimal IP lookalikes.
    if name.is_empty() || name.len() > 253 || !name.contains(&b'.') {
        return false;
    }
    if name.split(|b| *b == b'.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.first() == Some(&b'-')
            || label.last() == Some(&b'-')
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    }) {
        return false;
    }
    let last = name.rsplit(|b| *b == b'.').next().unwrap_or_default();
    !last.iter().all(u8::is_ascii_digit)
        && !(named
            && last.len() >= 2
            && last[0] == b'0'
            && matches!(last[1], b'x' | b'X')
            && last[2..].iter().all(u8::is_ascii_hexdigit))
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let Some((head, tail)) = self.0.split_at_checked(n) else {
            return invalid("invalid ECH config list");
        };
        self.0 = tail;
        Ok(head)
    }
    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn vector16(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
    fn end(self) -> Result<()> {
        if !self.0.is_empty() {
            return invalid("invalid ECH config list");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawEch {
    #[serde(default)]
    enable: bool,
    #[serde(default, deserialize_with = "deserialize_present_option")]
    config: Option<String>,
    #[serde(
        rename = "query-server-name",
        default,
        deserialize_with = "deserialize_present_option"
    )]
    query_server_name: Option<String>,
}

impl std::fmt::Debug for RawEch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawEch").finish_non_exhaustive()
    }
}

impl RawEch {
    pub(super) fn normalize(self, named: bool) -> Result<Option<StaticEchConfig>> {
        if !self.enable {
            return Ok(None);
        }
        if !cfg!(feature = "ech") {
            return invalid("ECH is not compiled in");
        }
        let encoded = self.config.unwrap_or_default();
        if encoded.is_empty() {
            let query = self.query_server_name.filter(|name| !name.is_empty());
            if let Some(name) = &query {
                crate::dns::canonicalize_name(name)
                    .map_err(|_| VoleError::InvalidConfig("invalid ECH query name".into()))?;
            }
            return Ok(Some(StaticEchConfig {
                wire: Vec::new(),
                source: std::sync::Arc::from([]),
                query: Some(query),
                named,
            }));
        }
        if encoded.len() > 87_384 {
            return invalid("ECH config exceeds the wire bound");
        }
        let wire = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| VoleError::InvalidConfig("invalid ECH Base64 config".into()))?;
        StaticEchConfig::from_config_list_for_backend(&wire, named).map(Some)
    }
}

pub(super) fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<RawEch>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_present_map(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid ECH options"))
}
