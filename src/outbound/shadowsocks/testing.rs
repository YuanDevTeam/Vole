//! Test-only bridge to actual SS carriers; no sockets, routes or cache.
use super::plugin::obfs_reuse_memory_tests::{ObfsMemoryGuard, memory_carrier};
use super::plugin::v2ray_mux_reuse_memory_tests::{MuxMemoryGuard, memory_mux_carrier};
use crate::{config::ShadowsocksCipher, dispatch::BoxStream, session::Destination};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
};

pub(crate) type AcceptedPeer =
    Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>>;

pub(crate) struct MemoryObfsFactory {
    cipher: ShadowsocksCipher,
    kind: CarrierKind,
    capacity: usize,
    guards: Mutex<Vec<Arc<CarrierGuard>>>,
}

#[derive(Clone, Copy)]
enum CarrierKind {
    Obfs { tls: bool },
    V2rayMux,
}
enum CarrierGuard {
    Obfs(ObfsMemoryGuard),
    V2rayMux(MuxMemoryGuard),
}
impl CarrierGuard {
    fn begin_shutdown(&self) {
        match self {
            Self::Obfs(guard) => guard.begin_shutdown(),
            Self::V2rayMux(guard) => guard.begin_shutdown(),
        }
    }
    async fn shutdown(&self) {
        match self {
            Self::Obfs(guard) => guard.shutdown().await,
            Self::V2rayMux(guard) => guard.shutdown().await,
        }
    }
    fn receipt(&self) -> super::plugin::obfs_reuse_memory_tests::ObfsMemoryReceipt {
        match self {
            Self::Obfs(guard) => guard.receipt(),
            Self::V2rayMux(guard) => guard.receipt(),
        }
    }
    fn mux_new(&self) -> usize {
        match self {
            Self::Obfs(_) => 0,
            Self::V2rayMux(guard) => guard.client_new(),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct MemoryObfsReceipt {
    pub(crate) owners: usize,
    pub(crate) opens: usize,
    pub(crate) target_handshakes: usize,
    pub(crate) cover_requests: usize,
    pub(crate) cover_responses: usize,
    pub(crate) client_drops: usize,
    pub(crate) peer_drops: usize,
    pub(crate) owner_cancelled: usize,
    pub(crate) owner_closed: usize,
    pub(crate) owner_wait_returned: usize,
    pub(crate) mux_new: usize,
}

impl MemoryObfsFactory {
    pub(crate) fn new(cipher: ShadowsocksCipher, tls: bool, capacity: usize) -> Arc<Self> {
        Self::with_kind(cipher, CarrierKind::Obfs { tls }, capacity)
    }

    pub(crate) fn new_v2ray_mux(cipher: ShadowsocksCipher, capacity: usize) -> Arc<Self> {
        Self::with_kind(cipher, CarrierKind::V2rayMux, capacity)
    }

    fn with_kind(cipher: ShadowsocksCipher, kind: CarrierKind, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            cipher,
            kind,
            capacity,
            guards: Mutex::new(Vec::new()),
        })
    }

    pub(crate) async fn open(&self, target: Destination) -> io::Result<(BoxStream, AcceptedPeer)> {
        let (client, accept, guard) = match self.kind {
            CarrierKind::Obfs { tls } => {
                let carrier = memory_carrier(self.cipher, tls, target, self.capacity).await?;
                drop(carrier.peer_write_blocked);
                (
                    carrier.client,
                    carrier.accept,
                    CarrierGuard::Obfs(carrier.guard),
                )
            }
            CarrierKind::V2rayMux => {
                let carrier = memory_mux_carrier(self.cipher, target, self.capacity).await?;
                (
                    carrier.client,
                    carrier.accept,
                    CarrierGuard::V2rayMux(carrier.guard),
                )
            }
        };
        self.guards
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(Arc::new(guard));
        // This notification belongs to the lower-layer backpressure test; R4
        // owns the original peer future and does not wait for a synthetic event.
        Ok((client, accept))
    }

    pub(crate) fn begin_shutdown(&self) {
        for guard in self
            .guards
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
        {
            guard.begin_shutdown();
        }
    }

    pub(crate) async fn shutdown(&self) {
        let guards = self
            .guards
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        for guard in &guards {
            guard.begin_shutdown();
        }
        // Never hold the registry lock across an owner wait. These guards do
        // not join external HTTP/TLS I/O; the real fixture parent does that.
        for guard in guards {
            guard.shutdown().await;
        }
    }

    pub(crate) fn snapshot(&self) -> MemoryObfsReceipt {
        let guards = self
            .guards
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut total = MemoryObfsReceipt {
            owners: guards.len(),
            ..Default::default()
        };
        for guard in guards.iter() {
            let receipt = guard.receipt();
            total.opens += receipt.opens;
            total.target_handshakes += receipt.target_handshakes;
            total.cover_requests += receipt.cover_requests;
            total.cover_responses += receipt.cover_responses;
            total.client_drops += receipt.client_drops;
            total.peer_drops += receipt.peer_drops;
            total.owner_cancelled += usize::from(receipt.owner_cancelled);
            total.owner_closed += usize::from(receipt.owner_closed);
            total.owner_wait_returned += usize::from(receipt.owner_wait_returned);
            total.mux_new += guard.mux_new();
        }
        total
    }
}
