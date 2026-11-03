//! File-backed client identities, published independently of the proxy graph.
//! The existing joined runtime worker owns all subsequent file reads.
use std::{
    io,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_util::sync::CancellationToken;

use crate::config::identity_files::{IdentityFileOrigin, PairStamp};

pub(super) struct IdentityMaterial {
    pub(super) certificates: Vec<CertificateDer<'static>>,
    pub(super) key: PrivateKeyDer<'static>,
    validated: OnceLock<bool>,
    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    native: Mutex<Weak<NativeIdentity>>,
}

#[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
pub(super) struct NativeIdentity {
    pub(super) certificates: Vec<boring::x509::X509>,
    pub(super) key: boring::pkey::PKey<boring::pkey::Private>,
}

impl IdentityMaterial {
    pub(super) fn new(
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        Self {
            certificates,
            key,
            validated: OnceLock::new(),
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            native: Mutex::new(Weak::new()),
        }
    }

    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    pub(super) fn native(&self) -> io::Result<Arc<NativeIdentity>> {
        let mut cached = self.native.lock().map_err(|_| invalid())?;
        if let Some(native) = cached.upgrade() {
            return Ok(native);
        }
        let certificates = self
            .certificates
            .iter()
            .map(|cert| boring::x509::X509::from_der(cert))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        let key = boring::pkey::PKey::private_key_from_der(self.key.secret_der())
            .map_err(|_| invalid())?;
        let leaf = certificates.first().ok_or_else(invalid)?;
        if !leaf.public_key().map_err(|_| invalid())?.public_eq(&key) {
            return Err(invalid());
        }
        let native = Arc::new(NativeIdentity { certificates, key });
        *cached = Arc::downgrade(&native);
        Ok(native)
    }

    pub(super) fn certified_key(&self) -> io::Result<Arc<rustls::sign::CertifiedKey>> {
        let size = self
            .certificates
            .iter()
            .try_fold(self.key.secret_der().len(), |size, cert| {
                size.checked_add(cert.len())
            });
        if size.is_none_or(|size| size > crate::config::MAX_CONFIG_BYTES) {
            return Err(invalid());
        }
        rustls::sign::CertifiedKey::from_der(
            self.certificates.clone(),
            self.key.clone_key(),
            &rustls::crypto::ring::default_provider(),
        )
        .map(Arc::new)
        .map_err(|_| invalid())
    }

    pub(super) fn validate(&self) -> io::Result<()> {
        if *self.validated.get_or_init(|| self.certified_key().is_ok()) {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

pub(super) struct IdentityGeneration {
    generation: u64,
    material: Arc<IdentityMaterial>,
    file_bytes: usize,
}

pub(super) struct ClientIdentitySource {
    origin: Arc<IdentityFileOrigin>,
    current: ArcSwap<IdentityGeneration>,
    attempted: Mutex<PairStamp>,
    stopped: Arc<AtomicBool>,
    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    native_users: Mutex<Weak<()>>,
    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    publication: Arc<Mutex<()>>,
}

#[derive(Clone, Default)]
pub(super) struct IdentityEpoch {
    generation: u64,
    source: Option<Weak<ClientIdentitySource>>,
}

impl IdentityEpoch {
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn is_current(&self) -> bool {
        self.source.as_ref().is_none_or(|source| {
            source.upgrade().is_some_and(|source| {
                !source.stopped.load(Ordering::Acquire)
                    && source.current.load().generation == self.generation
            })
        })
    }
}

pub(super) struct IdentitySnapshot {
    pub(super) material: Arc<IdentityMaterial>,
    pub(super) epoch: IdentityEpoch,
    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    pub(super) native: Option<Arc<NativeIdentity>>,
}

impl ClientIdentitySource {
    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    pub(super) fn native_lease(&self) -> io::Result<Arc<()>> {
        // The final publication check and first native registration use the
        // same short lock. Neither path parses certificates while holding it.
        let _publication = self.publication.lock().map_err(|_| invalid())?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(invalid());
        }
        let mut users = self.native_users.lock().map_err(|_| invalid())?;
        if let Some(lease) = users.upgrade() {
            return Ok(lease);
        }
        let lease = Arc::new(());
        *users = Arc::downgrade(&lease);
        Ok(lease)
    }

    #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
    pub(super) fn native_required(&self) -> bool {
        self.native_users
            .lock()
            .map_or(true, |users| users.strong_count() != 0)
    }

    pub(super) fn snapshot(self: &Arc<Self>) -> IdentitySnapshot {
        let current = self.current.load_full();
        IdentitySnapshot {
            material: current.material.clone(),
            epoch: IdentityEpoch {
                generation: current.generation,
                source: Some(Arc::downgrade(self)),
            },
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            native: None,
        }
    }
}

/// Weak membership prevents retired nodes or a stopped runtime from retaining
/// complete graphs. Identical explicit file pairs may share material, while
/// every TLS node/leg retains its own immutable policy and ticket budget.
#[derive(Default)]
pub(crate) struct IdentityRegistry {
    sources: Mutex<Vec<Weak<ClientIdentitySource>>>,
    publication: Arc<Mutex<()>>,
    stopped: Arc<AtomicBool>,
}

impl IdentityRegistry {
    pub(crate) fn has_sources(&self) -> bool {
        !self.stopped.load(Ordering::Acquire)
            && self
                .sources
                .lock()
                .is_ok_and(|sources| sources.iter().any(|source| source.strong_count() != 0))
    }

    pub(crate) fn begin_shutdown(&self) {
        let _publication = self.publication.lock();
        self.stopped.store(true, Ordering::Release);
    }

    pub(super) fn register(
        &self,
        origin: &Arc<IdentityFileOrigin>,
        initial: Arc<IdentityMaterial>,
        file_bytes: usize,
    ) -> io::Result<Arc<ClientIdentitySource>> {
        let mut sources = self.sources.lock().map_err(|_| invalid())?;
        let _publication = self.publication.lock().map_err(|_| invalid())?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(invalid());
        }
        sources.retain(|source| source.strong_count() != 0);
        let mut used = 0_usize;
        let mut existing = None;
        for source in sources.iter().filter_map(Weak::upgrade) {
            used = used.saturating_add(source.current.load().file_bytes);
            if source.origin.same_files(origin) {
                existing = Some(source);
            }
        }
        if let Some(source) = existing {
            let other_bytes = used.saturating_sub(source.current.load().file_bytes);
            if other_bytes.saturating_add(file_bytes) > crate::config::MAX_CONFIG_BYTES {
                return Err(invalid());
            }
            return Ok(source);
        }
        if used.saturating_add(file_bytes) > crate::config::MAX_CONFIG_BYTES {
            return Err(invalid());
        }
        let source = Arc::new(ClientIdentitySource {
            origin: origin.clone(),
            current: ArcSwap::from_pointee(IdentityGeneration {
                generation: 1,
                material: initial,
                file_bytes,
            }),
            attempted: Mutex::new(origin.initial.clone()),
            stopped: self.stopped.clone(),
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            native_users: Mutex::new(Weak::new()),
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            publication: self.publication.clone(),
        });
        sources.push(Arc::downgrade(&source));
        Ok(source)
    }

    /// Called only by the existing joined maintenance worker. Metadata probes
    /// and PEM input are bounded; a failed pair preserves the published identity.
    pub(crate) fn refresh(&self, cancellation: &CancellationToken) {
        #[cfg(test)]
        self.refresh_inner(cancellation, None);
        #[cfg(not(test))]
        self.refresh_inner(cancellation);
    }

    #[cfg(test)]
    pub(super) fn refresh_before_publication(
        &self,
        cancellation: &CancellationToken,
        before: &mut dyn FnMut(),
    ) {
        self.refresh_inner(cancellation, Some(before));
    }

    fn refresh_inner(
        &self,
        cancellation: &CancellationToken,
        #[cfg(test)] mut before: Option<&mut dyn FnMut()>,
    ) {
        if cancellation.is_cancelled() || self.stopped.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut entries) = self.sources.lock() else {
            return;
        };
        entries.retain(|source| source.strong_count() != 0);
        let sources: Vec<_> = entries.iter().filter_map(Weak::upgrade).collect();
        // Serialize registration/publication so the aggregate active material
        // budget cannot be bypassed by concurrent candidate graph preparation.
        let mut used: usize = sources
            .iter()
            .map(|source| source.current.load().file_bytes)
            .sum();
        for source in &sources {
            if cancellation.is_cancelled() || self.stopped.load(Ordering::Acquire) {
                return;
            }
            let Ok(stamp) = source.origin.stamp() else {
                continue;
            };
            let Ok(mut attempted) = source.attempted.lock() else {
                continue;
            };
            if *attempted == stamp {
                continue;
            }
            let old = source.current.load_full();
            let other_bytes = used.saturating_sub(old.file_bytes);
            let Some(mut remaining) = crate::config::MAX_CONFIG_BYTES.checked_sub(other_bytes)
            else {
                continue;
            };
            // Oversized pairs may become admissible after another identity is
            // removed or shrinks; do not remember an unsuccessful budget check.
            if stamp.bytes() > remaining {
                continue;
            }
            let Ok((certificate, private_key, read_stamp)) = source.origin.read(&mut remaining)
            else {
                continue;
            };
            if read_stamp != stamp
                || source.origin.stamp().ok().as_ref() != Some(&read_stamp)
                || cancellation.is_cancelled()
            {
                continue;
            }
            // Only stable content failures are remembered. Permission and IO
            // recovery must work even when size/mtime/inode stay unchanged.
            *attempted = read_stamp.clone();
            let file_bytes = certificate.len().saturating_add(private_key.len());
            let Ok(identity) = super::tls::TlsClientIdentity::from_pem(&certificate, &private_key)
            else {
                continue;
            };
            let material = identity.snapshot().material;
            if material.validate().is_err()
                || source.origin.stamp().ok().as_ref() != Some(&read_stamp)
                || cancellation.is_cancelled()
            {
                continue;
            }
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            let mut native_validation = if source.native_required() {
                let Ok(native) = material.native() else {
                    continue;
                };
                Some(native)
            } else {
                None
            };
            let Some(generation) = old.generation.checked_add(1) else {
                continue;
            };
            #[cfg(test)]
            if let Some(before) = &mut before {
                before();
            }
            let Ok(publication) = self.publication.lock() else {
                return;
            };
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            let mut publication = publication;
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            if source.native_required() && native_validation.is_none() {
                // A native client registered after the first check. Complete
                // validation outside the Stop/publication lock, then reenter.
                drop(publication);
                let Ok(native) = material.native() else {
                    continue;
                };
                native_validation = Some(native);
                let Ok(guard) = self.publication.lock() else {
                    return;
                };
                publication = guard;
            }
            if cancellation.is_cancelled() || self.stopped.load(Ordering::Acquire) {
                return;
            }
            source.current.store(Arc::new(IdentityGeneration {
                generation,
                material,
                file_bytes,
            }));
            drop(publication);
            #[cfg(any(feature = "tls-fingerprint", feature = "quiche-h3-transport"))]
            drop(native_validation);
            used = other_bytes.saturating_add(file_bytes);
        }
    }
}

pub(super) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS client identity")
}

#[cfg(all(
    test,
    any(feature = "tls-fingerprint", feature = "quiche-h3-transport")
))]
mod tests {
    use super::*;

    #[test]
    fn ordinary_rustls_identity_does_not_retain_an_unused_native_representation() {
        let generated = rcgen::generate_simple_self_signed(vec!["client.invalid".into()]).unwrap();
        let identity = super::super::TlsClientIdentity::from_der(
            vec![generated.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                .into(),
        );
        let snapshot = identity.snapshot();
        let _client = super::super::StandardTlsClient::with_options(
            &super::super::SecurityContext::new(),
            "peer.invalid",
            super::super::TlsClientOptions {
                identity: Some(identity.clone()),
                ..Default::default()
            },
            0,
            65536,
        )
        .unwrap();
        assert_eq!(snapshot.material.native.lock().unwrap().strong_count(), 0);
        let native_client = identity.for_native().unwrap();
        let first = native_client.native_snapshot().unwrap().native.unwrap();
        let second = native_client.native_snapshot().unwrap().native.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let cached = Arc::downgrade(&first);
        drop((first, second));
        assert!(cached.upgrade().is_some());
        drop(native_client);
        assert!(cached.upgrade().is_none());
    }
}
