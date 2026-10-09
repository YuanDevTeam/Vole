//! Running-session connection ownership and opt-in Controller snapshots.
use crate::dispatch::{BoxStream, DispatchError};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub(crate) struct Registry {
    entries: Mutex<BTreeMap<String, Arc<Entry>>>,
    failures: Mutex<VecDeque<Value>>,
    upload: AtomicU64,
    download: AtomicU64,
    closed: AtomicBool,
}
struct Entry {
    metadata: Mutex<Value>,
    start: String,
    upload: AtomicU64,
    download: AtomicU64,
    cancel: CancellationToken,
}
pub(crate) struct Connection {
    id: String,
    entry: Arc<Entry>,
    registry: Weak<Registry>,
}
impl Registry {
    pub fn open(self: &Arc<Self>, metadata: Value) -> Connection {
        let id = uuid::Builder::from_random_bytes(rand::random())
            .into_uuid()
            .to_string();
        let entry = Arc::new(Entry {
            metadata: Mutex::new(metadata),
            start: timestamp(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            cancel: CancellationToken::new(),
        });
        let mut entries = self.entries.lock().unwrap();
        if self.closed.load(Ordering::Acquire) {
            entry.cancel.cancel();
        } else {
            entries.insert(id.clone(), entry.clone());
        }
        Connection {
            id,
            entry,
            registry: Arc::downgrade(self),
        }
    }
    pub fn snapshot(&self) -> Value {
        let connections = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|(id, entry)| {
                let mut value = entry.metadata.lock().unwrap().clone();
                value["id"] = json!(id);
                value["start"] = json!(entry.start);
                value["upload"] = json!(entry.upload.load(Ordering::Relaxed));
                value["download"] = json!(entry.download.load(Ordering::Relaxed));
                value
            })
            .collect::<Vec<_>>();
        json!({"uploadTotal": self.upload.load(Ordering::Relaxed), "downloadTotal": self.download.load(Ordering::Relaxed), "connections": connections, "memory": 0, "errors": self.failures.lock().unwrap().iter().cloned().collect::<Vec<_>>()})
    }
    pub fn close(&self, id: &str) {
        if let Some(entry) = self.entries.lock().unwrap().remove(id) {
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
        self.entry.metadata.lock().unwrap()["dnsPath"] = json!(path);
    }
    pub fn token(&self) -> CancellationToken {
        self.entry.cancel.clone()
    }
    pub fn cancelled(&self) -> bool {
        self.entry.cancel.is_cancelled()
    }
    pub fn upload(&self, bytes: usize) {
        saturating_add(&self.entry.upload, bytes);
        if let Some(registry) = self.registry.upgrade() {
            saturating_add(&registry.upload, bytes);
        }
    }
    pub fn download(&self, bytes: usize) {
        saturating_add(&self.entry.download, bytes);
        if let Some(registry) = self.registry.upgrade() {
            saturating_add(&registry.download, bytes);
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
        let mut failures = registry.failures.lock().unwrap();
        if failures.len() == 32 {
            failures.pop_front();
        }
        let mut info = self.entry.metadata.lock().unwrap().clone();
        info["id"] = json!(self.id);
        info["time"] = json!(timestamp());
        info["error"] = json!(kind);
        failures.push_back(info);
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
            registry.entries.lock().unwrap().remove(&self.id);
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
pub(crate) fn timestamp() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("current UTC date")
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn connection_query_counts_and_close_wakes_blocked_io() {
        let registry = Arc::new(Registry::default());
        let connection = registry.open(json!({"metadata":{"network":"tcp"},"chains":["edge","auto"],"rule":"DomainSuffix","rulePayload":"example.com"}));
        let id = connection.id.clone();
        let (client, mut peer) = tokio::io::duplex(32);
        let mut stream = connection.stream(Box::new(client));
        stream.write_all(b"sent").await.unwrap();
        peer.write_all(b"ok").await.unwrap();
        assert_eq!(stream.read_u16().await.unwrap(), u16::from_be_bytes(*b"ok"));
        let snapshot = registry.snapshot();
        assert_eq!(snapshot["connections"][0]["upload"], 4);
        assert_eq!(snapshot["connections"][0]["download"], 2);
        assert_eq!(
            snapshot["connections"][0]["chains"],
            json!(["edge", "auto"])
        );
        let waiting = tokio::spawn(async move { stream.read_u8().await });
        tokio::task::yield_now().await;
        registry.close(&id);
        assert_eq!(
            waiting.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(
            registry.snapshot()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(registry.snapshot()["uploadTotal"], 4);
        registry.shutdown();
        assert!(registry.open(json!({})).cancelled());
    }
}
