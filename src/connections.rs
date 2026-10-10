//! Running-session connection ownership and opt-in Controller snapshots.
use crate::dispatch::{BoxStream, DispatchError};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

/// Only owned presentation data is retained, never its resource generation.
pub(crate) struct ConnectionInfo {
    pub metadata: ConnectionMetadata,
    pub chains: Vec<Arc<str>>,
    pub provider_chains: Vec<Arc<str>>,
    pub rule: &'static str,
    pub rule_payload: Arc<str>,
    pub dns_path: Vec<&'static str>,
}
pub(crate) struct ConnectionMetadata {
    pub network: &'static str,
    pub inbound_type: &'static str,
    pub source: SocketAddr,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: u16,
    pub host: Arc<str>,
    pub dns_mode: &'static str,
    pub sniff_host: Arc<str>,
}
impl Serialize for ConnectionMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ConnectionMetadata", 9)?;
        state.serialize_field("network", self.network)?;
        state.serialize_field("type", self.inbound_type)?;
        state.serialize_field("sourceIP", &self.source.ip())?;
        state.serialize_field("sourcePort", &Port(self.source.port()))?;
        state.serialize_field("destinationIP", &self.destination_ip)?;
        state.serialize_field("destinationPort", &Port(self.destination_port))?;
        state.serialize_field("host", self.host.as_ref())?;
        state.serialize_field("dnsMode", self.dns_mode)?;
        state.serialize_field("sniffHost", self.sniff_host.as_ref())?;
        state.end()
    }
}
struct Port(u16);
impl Serialize for Port {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}
struct Details {
    metadata: ConnectionMetadata,
    chains: Box<[Arc<str>]>,
    provider_chains: Box<[Arc<str>]>,
    rule: &'static str,
    rule_payload: Arc<str>,
}
impl Details {
    fn serialize_fields<S: SerializeStruct>(
        &self,
        state: &mut S,
        dns_path: &[&'static str],
    ) -> Result<(), S::Error> {
        state.serialize_field("metadata", &self.metadata)?;
        state.serialize_field("chains", &SharedSlice(&self.chains))?;
        state.serialize_field("providerChains", &SharedSlice(&self.provider_chains))?;
        state.serialize_field("rule", self.rule)?;
        state.serialize_field("rulePayload", self.rule_payload.as_ref())?;
        state.serialize_field("dnsPath", dns_path)
    }
}
#[derive(Default)]
struct SessionCounters {
    upload: AtomicU64,
    download: AtomicU64,
}
#[derive(Default)]
pub(crate) struct Registry {
    entries: Mutex<BTreeMap<uuid::Uuid, Arc<Entry>>>,
    failures: Mutex<VecDeque<Arc<Failure>>>,
    totals: Arc<SessionCounters>,
    closed: AtomicBool,
}
struct Entry {
    id: uuid::Uuid,
    details: Arc<Details>,
    dns_path: Mutex<Arc<[&'static str]>>,
    start: Timestamp,
    upload: AtomicU64,
    download: AtomicU64,
    cancel: CancellationToken,
}
struct ConnectionSnapshot {
    id: uuid::Uuid,
    details: Arc<Details>,
    dns_path: Arc<[&'static str]>,
    start: Timestamp,
    upload: u64,
    download: u64,
}
impl ConnectionSnapshot {
    fn capture(entry: &Entry) -> Self {
        Self {
            id: entry.id,
            details: entry.details.clone(),
            dns_path: entry.dns_path.lock().unwrap().clone(),
            start: entry.start,
            upload: entry.upload.load(Ordering::Relaxed),
            download: entry.download.load(Ordering::Relaxed),
        }
    }
}
impl Serialize for ConnectionSnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Connection", 10)?;
        self.details.serialize_fields(&mut state, &self.dns_path)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("start", &self.start)?;
        state.serialize_field("upload", &self.upload)?;
        state.serialize_field("download", &self.download)?;
        state.end()
    }
}
struct Failure {
    id: uuid::Uuid,
    details: Arc<Details>,
    dns_path: Arc<[&'static str]>,
    time: Timestamp,
    error: &'static str,
}
impl Serialize for Failure {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ConnectionFailure", 9)?;
        self.details.serialize_fields(&mut state, &self.dns_path)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("time", &self.time)?;
        state.serialize_field("error", self.error)?;
        state.end()
    }
}
/// The query freezes values outside the registry lock and shares immutable text.
/// It can outlive removal without extending transport/cancellation ownership.
pub(crate) struct Snapshot {
    connections: Vec<ConnectionSnapshot>,
    failures: Vec<Arc<Failure>>,
    memory: Option<u64>,
    upload: u64,
    download: u64,
}
impl Serialize for Snapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Connections", 5)?;
        state.serialize_field("uploadTotal", &self.upload)?;
        state.serialize_field("downloadTotal", &self.download)?;
        state.serialize_field("connections", &self.connections)?;
        state.serialize_field("memory", &self.memory)?;
        state.serialize_field("errors", &SharedSlice(&self.failures))?;
        state.end()
    }
}
struct SharedSlice<'a, T: ?Sized>(&'a [Arc<T>]);
impl<T: Serialize + ?Sized> Serialize for SharedSlice<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for item in self.0 {
            sequence.serialize_element(item.as_ref())?;
        }
        sequence.end()
    }
}
pub(crate) struct Connection {
    entry: Arc<Entry>,
    totals: Arc<SessionCounters>,
    registry: Weak<Registry>,
    business_totals: bool,
}
impl Registry {
    pub fn open(self: &Arc<Self>, info: ConnectionInfo) -> Connection {
        self.open_counted(info, true)
    }
    #[cfg(feature = "sing-mux")]
    pub(crate) fn open_inner(self: &Arc<Self>, info: ConnectionInfo) -> Connection {
        self.open_counted(info, false)
    }
    fn open_counted(self: &Arc<Self>, info: ConnectionInfo, business_totals: bool) -> Connection {
        let entry = Arc::new(Entry {
            id: uuid::Builder::from_random_bytes(rand::random()).into_uuid(),
            details: Arc::new(Details {
                metadata: info.metadata,
                chains: info.chains.into_boxed_slice(),
                provider_chains: info.provider_chains.into_boxed_slice(),
                rule: info.rule,
                rule_payload: info.rule_payload,
            }),
            dns_path: Mutex::new(info.dns_path.into()),
            start: Timestamp::now(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            cancel: CancellationToken::new(),
        });
        let mut entries = self.entries.lock().unwrap();
        if self.closed.load(Ordering::Acquire) {
            entry.cancel.cancel();
        } else {
            entries.insert(entry.id, entry.clone());
        }
        Connection {
            entry,
            totals: self.totals.clone(),
            registry: Arc::downgrade(self),
            business_totals,
        }
    }
    pub fn snapshot(&self) -> Snapshot {
        let entries = self
            .entries
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let connections = entries
            .into_iter()
            .map(|entry| ConnectionSnapshot::capture(&entry))
            .collect();
        let failures = self.failures.lock().unwrap().iter().cloned().collect();
        Snapshot {
            connections,
            failures,
            memory: crate::memory::resident_bytes(),
            upload: self.totals.upload.load(Ordering::Relaxed),
            download: self.totals.download.load(Ordering::Relaxed),
        }
    }
    pub fn close(&self, id: &str) {
        let Ok(parsed) = uuid::Uuid::parse_str(id) else {
            return;
        };
        // Preserve exact canonical IDs: noncanonical spellings remain unknown.
        if parsed
            .hyphenated()
            .encode_lower(&mut uuid::Uuid::encode_buffer())
            != id
        {
            return;
        }
        let entry = self.entries.lock().unwrap().remove(&parsed);
        if let Some(entry) = entry {
            entry.cancel.cancel();
        }
    }
    pub fn close_all(&self) {
        let entries = std::mem::take(&mut *self.entries.lock().unwrap());
        for entry in entries.into_values() {
            entry.cancel.cancel();
        }
    }
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.close_all();
    }
}
impl Connection {
    pub fn dns_path(&self, path: Vec<&'static str>) {
        *self.entry.dns_path.lock().unwrap() = path.into();
    }
    pub fn token(&self) -> CancellationToken {
        self.entry.cancel.clone()
    }
    pub fn cancelled(&self) -> bool {
        self.entry.cancel.is_cancelled()
    }
    pub fn upload(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        saturating_add(&self.entry.upload, bytes);
        if self.business_totals {
            saturating_add(&self.totals.upload, bytes);
        }
    }
    pub fn download(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        saturating_add(&self.entry.download, bytes);
        if self.business_totals {
            saturating_add(&self.totals.download, bytes);
        }
    }
    pub fn failed(&self, error: &DispatchError) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let kind = match error {
            DispatchError::NotAllowed => "not_allowed",
            DispatchError::TimedOut => "timed_out",
            DispatchError::HostUnreachable => "host_unreachable",
            DispatchError::NetworkUnreachable => "network_unreachable",
            _ => "outbound_failed",
        };
        let failure = Arc::new(Failure {
            id: self.entry.id,
            details: self.entry.details.clone(),
            dns_path: self.entry.dns_path.lock().unwrap().clone(),
            time: Timestamp::now(),
            error: kind,
        });
        let mut failures = registry.failures.lock().unwrap();
        if failures.len() == 32 {
            failures.pop_front();
        }
        failures.push_back(failure);
    }
    pub fn stream(self, inner: BoxStream) -> BoxStream {
        let cancelled = Box::pin(self.token().cancelled_owned());
        Box::new(TrackedStream {
            connection: self,
            inner: Some(inner),
            cancelled,
        })
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.entries.lock().unwrap().remove(&self.entry.id);
        }
    }
}
fn saturating_add(counter: &AtomicU64, bytes: usize) {
    let mut old = counter.load(Ordering::Relaxed);
    while let Err(value) = counter.compare_exchange_weak(
        old,
        old.saturating_add(bytes as u64),
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        old = value;
    }
}
#[derive(Clone, Copy)]
struct Timestamp(i128);
impl Timestamp {
    fn now() -> Self {
        Self(time::OffsetDateTime::now_utc().unix_timestamp_nanos())
    }
    fn format(&self) -> String {
        time::OffsetDateTime::from_unix_timestamp_nanos(self.0)
            .expect("recorded UTC date")
            .format(&time::format_description::well_known::Rfc3339)
            .expect("recorded UTC date")
    }
}
impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.format())
    }
}
struct TrackedStream {
    connection: Connection,
    inner: Option<BoxStream>,
    cancelled: Pin<Box<tokio_util::sync::WaitForCancellationFutureOwned>>,
}
impl TrackedStream {
    fn closed(&mut self, cx: &mut Context<'_>) -> bool {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            self.inner.take();
        }
        self.inner.is_none()
    }
}
fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")
}
impl AsyncRead for TrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed(cx) {
            return Poll::Ready(Err(closed_error()));
        }
        let before = buffer.filled().len();
        let result = Pin::new(self.inner.as_mut().expect("open stream")).poll_read(cx, buffer);
        self.connection.download(buffer.filled().len() - before);
        result
    }
}
impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed(cx) {
            return Poll::Ready(Err(closed_error()));
        }
        let result = Pin::new(self.inner.as_mut().expect("open stream")).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = &result {
            self.connection.upload(*n);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed(cx) {
            return Poll::Ready(Err(closed_error()));
        }
        Pin::new(self.inner.as_mut().expect("open stream")).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed(cx) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(self.inner.as_mut().expect("open stream")).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn info() -> ConnectionInfo {
        ConnectionInfo {
            metadata: ConnectionMetadata {
                network: "tcp",
                inbound_type: "Socks5",
                source: "127.0.0.1:1234".parse().unwrap(),
                destination_ip: Some("198.51.100.1".parse().unwrap()),
                destination_port: 443,
                host: "example.com".into(),
                dns_mode: "normal",
                sniff_host: "".into(),
            },
            chains: vec!["edge".into(), "auto".into()],
            provider_chains: vec!["nodes".into()],
            rule: "DomainSuffix",
            rule_payload: "example.com".into(),
            dns_path: vec!["cache"],
        }
    }
    fn view(registry: &Registry) -> Value {
        serde_json::to_value(registry.snapshot()).unwrap()
    }
    #[tokio::test]
    async fn connection_query_counts_and_close_wakes_blocked_io() {
        let registry = Arc::new(Registry::default());
        let connection = registry.open(info());
        let id = connection.entry.id.to_string();
        let (client, mut peer) = tokio::io::duplex(32);
        let mut stream = connection.stream(Box::new(client));
        stream.write_all(b"sent").await.unwrap();
        peer.write_all(b"ok").await.unwrap();
        assert_eq!(stream.read_u16().await.unwrap(), u16::from_be_bytes(*b"ok"));
        let snapshot = view(&registry);
        assert_eq!(snapshot["connections"][0]["upload"], 4);
        assert_eq!(snapshot["connections"][0]["download"], 2);
        assert_eq!(
            snapshot["connections"][0]["chains"],
            json!(["edge", "auto"])
        );
        assert_eq!(snapshot["connections"][0]["metadata"]["sourcePort"], "1234");
        assert_eq!(
            snapshot["connections"][0]["metadata"]["destinationPort"],
            "443"
        );
        let waiting = tokio::spawn(async move { stream.read_u8().await });
        tokio::task::yield_now().await;
        registry.close(&id);
        assert_eq!(
            waiting.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(
            view(&registry)["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(view(&registry)["uploadTotal"], 4);
        registry.shutdown();
        assert!(registry.open(info()).cancelled());
    }

    #[test]
    fn query_snapshot_freezes_counters_and_dns_path_before_later_io() {
        let registry = Arc::new(Registry::default());
        let connection = registry.open(info());
        connection.upload(3);
        connection.download(5);
        let snapshot = registry.snapshot();
        let before = serde_json::to_value(&snapshot).unwrap();
        connection.upload(7);
        connection.download(11);
        connection.dns_path(vec!["fallback"]);
        connection.failed(&DispatchError::TimedOut);
        let after = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(after, before, "query data must not change after capture");
        assert_eq!(after["connections"][0]["upload"], 3);
        assert_eq!(after["connections"][0]["download"], 5);
        assert_eq!(after["connections"][0]["dnsPath"], json!(["cache"]));
        assert_eq!(after["uploadTotal"], 3);
        assert!(after["errors"].as_array().unwrap().is_empty());
        assert_eq!(view(&registry)["uploadTotal"], 10);
        assert_eq!(view(&registry)["downloadTotal"], 16);
    }

    #[test]
    fn snapshot_shares_metadata_without_holding_registry_or_live_connection() {
        let registry = Arc::new(Registry::default());
        let connection = registry.open(info());
        let details = Arc::downgrade(&connection.entry.details);
        let entry = Arc::downgrade(&connection.entry);
        let snapshot = registry.snapshot();
        assert!(Arc::ptr_eq(
            &snapshot.connections[0].details,
            &connection.entry.details
        ));
        registry.close_all();
        assert!(connection.cancelled());
        drop(connection);
        assert!(
            entry.upgrade().is_none(),
            "a query must release the I/O cancellation owner"
        );
        assert!(
            view(&registry)["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let weak_registry = Arc::downgrade(&registry);
        drop(registry);
        assert!(weak_registry.upgrade().is_none());
        assert_eq!(
            serde_json::to_value(&snapshot).unwrap()["connections"][0]["chains"],
            json!(["edge", "auto"])
        );
        drop(snapshot);
        assert!(details.upgrade().is_none());
    }

    #[test]
    fn exact_counters_saturate_and_outlive_registry_without_io_weak_upgrade() {
        let registry = Arc::new(Registry::default());
        let connection = registry.open(info());
        connection.upload(0);
        connection.download(0);
        assert_eq!(view(&registry)["uploadTotal"], 0);
        std::thread::scope(|scope| {
            for _ in 0..6 {
                scope.spawn(|| {
                    for _ in 0..1_000 {
                        connection.upload(1);
                        connection.download(2);
                    }
                });
            }
        });
        assert_eq!(view(&registry)["uploadTotal"], 6_000);
        assert_eq!(view(&registry)["downloadTotal"], 12_000);
        assert_eq!(connection.entry.upload.load(Ordering::Relaxed), 6_000);
        assert_eq!(connection.entry.download.load(Ordering::Relaxed), 12_000);
        connection
            .entry
            .upload
            .store(u64::MAX - 1, Ordering::Relaxed);
        registry
            .totals
            .upload
            .store(u64::MAX - 1, Ordering::Relaxed);
        connection.upload(4);
        assert_eq!(connection.entry.upload.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(view(&registry)["uploadTotal"], u64::MAX);
        let totals = registry.totals.clone();
        drop(registry);
        connection.download(7);
        assert_eq!(totals.download.load(Ordering::Relaxed), 12_007);
    }

    #[test]
    fn failure_history_is_bounded_and_keeps_its_dns_path_after_connection_updates() {
        let registry = Arc::new(Registry::default());
        let connection = registry.open(info());
        for _ in 0..33 {
            connection.failed(&DispatchError::TimedOut);
        }
        connection.dns_path(vec!["fallback"]);
        let snapshot = view(&registry);
        assert_eq!(snapshot["errors"].as_array().unwrap().len(), 32);
        assert_eq!(snapshot["errors"][0]["error"], "timed_out");
        assert_eq!(snapshot["errors"][0]["dnsPath"], json!(["cache"]));
        assert_eq!(snapshot["connections"][0]["dnsPath"], json!(["fallback"]));
        assert!(snapshot["errors"][0].get("start").is_none());
        assert!(snapshot["errors"][0].get("upload").is_none());
    }
}
