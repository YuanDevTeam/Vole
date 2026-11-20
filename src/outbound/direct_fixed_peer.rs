//! One immutable peer on a fresh protected DIRECT path; no socket factory.
use crate::dispatch::DispatchError;
use std::{future::Future, net::SocketAddr, sync::Arc};

pub(super) struct Path<S> {
    peer: SocketAddr,
    attempted: bool,
    closed: bool,
    socket: Option<Arc<S>>,
}

impl<S> Path<S> {
    pub(super) fn new(peer: SocketAddr) -> Result<Self, DispatchError> {
        if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast() {
            return Err(DispatchError::NotAllowed);
        }
        Ok(Self {
            peer,
            attempted: false,
            closed: false,
            socket: None,
        })
    }

    pub(super) fn ready(&self, peer: SocketAddr) -> Result<Option<Arc<S>>, DispatchError> {
        if self.closed || peer != self.peer {
            return Err(DispatchError::NotAllowed);
        }
        Ok(self.socket.clone())
    }

    pub(super) async fn initialize_with<B, BF, C, CF>(
        &mut self,
        peer: SocketAddr,
        prepare: B,
        connect: C,
    ) -> Result<Arc<S>, DispatchError>
    where
        B: FnOnce(SocketAddr) -> BF,
        BF: Future<Output = Result<S, DispatchError>>,
        C: FnOnce(S, SocketAddr) -> CF,
        CF: Future<Output = Result<S, DispatchError>>,
    {
        if let Some(socket) = self.ready(peer)? {
            return Ok(socket);
        }
        if self.attempted {
            return Err(DispatchError::NotAllowed);
        }
        // Reserve one attempt before any await. Failure or cancellation never
        // permits another bind/connect on this physical generation.
        self.attempted = true;
        let socket = prepare(self.peer).await?;
        let socket = connect(socket, self.peer).await?;
        // Only the successful, original prepared socket is published.
        let socket = Arc::new(socket);
        self.socket = Some(socket.clone());
        Ok(socket)
    }

    pub(super) fn close(&mut self) {
        self.closed = true;
        self.socket.take();
    }
}

#[cfg(test)]
mod tests {
    use super::super::DirectDatagramTransport;
    use super::*;
    use crate::{
        dialer::Dialer,
        dispatch::DatagramTransport,
        session::{Datagram, Destination},
    };
    use bytes::Bytes;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct Lease {
        token: usize,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn peer() -> SocketAddr {
        SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            443,
            123,
            7,
        ))
    }
    fn packet(remote: Destination) -> Datagram {
        Datagram {
            remote,
            payload: Bytes::from_static(b"whole"),
            sniffed_domain: None,
        }
    }

    #[tokio::test]
    async fn fixed_udp_memory_prepared_owner_connects_once_and_publishes_only_success() {
        let peer = peer();
        let events = Arc::new(Mutex::new(Vec::new()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut path = Path::<Lease>::new(peer).unwrap();
        assert!(path.ready(peer).unwrap().is_none());
        let prepared = events.clone();
        let connected = events.clone();
        let owned_drops = drops.clone();
        let socket = path
            .initialize_with(
                peer,
                move |actual| async move {
                    assert_eq!(actual, peer);
                    prepared
                        .lock()
                        .unwrap()
                        .push("protected-preparation-returned");
                    Ok(Lease {
                        token: 17,
                        drops: owned_drops,
                    })
                },
                move |socket, actual| async move {
                    assert_eq!(actual, peer);
                    assert_eq!(socket.token, 17);
                    connected.lock().unwrap().push("connect-original-owner");
                    Ok(socket)
                },
            )
            .await
            .unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            ["protected-preparation-returned", "connect-original-owner"]
        );
        assert!(Arc::ptr_eq(&socket, &path.ready(peer).unwrap().unwrap()));
        let again = path
            .initialize_with(
                peer,
                |_| async { panic!("a connected generation must not prepare again") },
                |_, _| async { panic!("a connected generation must not connect again") },
            )
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&socket, &again));
        drop(again);
        path.close();
        assert!(path.ready(peer).is_err());
        assert_eq!(
            drops.load(Ordering::Relaxed),
            0,
            "the returned owned lease remains real"
        );
        drop(socket);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fixed_udp_memory_preparation_refusal_never_connects_or_retries() {
        let peer = peer();
        let calls = Arc::new(AtomicUsize::new(0));
        let connect_calls = calls.clone();
        let mut path = Path::<Lease>::new(peer).unwrap();
        let result = path
            .initialize_with(
                peer,
                |_| async { Err(DispatchError::NotAllowed) },
                move |socket, _| async move {
                    connect_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(socket)
                },
            )
            .await;
        assert!(matches!(result, Err(DispatchError::NotAllowed)));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(path.ready(peer).unwrap().is_none());
        let retry = path
            .initialize_with(
                peer,
                |_| async { panic!("failed protected preparation cannot rebind") },
                |_, _| async { panic!("failed protected preparation cannot connect") },
            )
            .await;
        assert!(matches!(retry, Err(DispatchError::NotAllowed)));
        path.close();
    }

    #[tokio::test]
    async fn fixed_udp_memory_connect_error_preserves_error_and_drops_unpublished_owner() {
        let peer = peer();
        let drops = Arc::new(AtomicUsize::new(0));
        let owned_drops = drops.clone();
        let mut path = Path::<Lease>::new(peer).unwrap();
        let result = path
            .initialize_with(
                peer,
                move |_| async move {
                    Ok(Lease {
                        token: 17,
                        drops: owned_drops,
                    })
                },
                |socket, _| async move {
                    assert_eq!(socket.token, 17);
                    Err(DispatchError::Other("original-connect-error".to_owned()))
                },
            )
            .await;
        assert!(
            matches!(result, Err(DispatchError::Other(value)) if value == "original-connect-error")
        );
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(path.ready(peer).unwrap().is_none());
        assert!(matches!(
            path.initialize_with(
                peer,
                |_| async { panic!("connect failure must not allocate a replacement") },
                |_, _| async { panic!("connect failure must not reconnect") },
            )
            .await,
            Err(DispatchError::NotAllowed)
        ));
    }

    #[tokio::test]
    async fn fixed_udp_memory_cancelled_preparation_or_connect_releases_owner_without_reconnect() {
        for pending_connect in [false, true] {
            let peer = peer();
            let drops = Arc::new(AtomicUsize::new(0));
            let owned_drops = drops.clone();
            let mut path = Path::<Lease>::new(peer).unwrap();
            let mut initializing = Box::pin(path.initialize_with(
                peer,
                move |_| async move {
                    let socket = Lease {
                        token: 17,
                        drops: owned_drops,
                    };
                    if !pending_connect {
                        let _held = socket;
                        return std::future::pending::<Result<Lease, DispatchError>>().await;
                    }
                    Ok(socket)
                },
                |socket, _| async move {
                    let _held = socket;
                    std::future::pending::<Result<Lease, DispatchError>>().await
                },
            ));
            assert!(futures_util::poll!(initializing.as_mut()).is_pending());
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            drop(initializing);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert!(path.ready(peer).unwrap().is_none());
            assert!(matches!(
                path.initialize_with(
                    peer,
                    |_| async { panic!("cancelled initialization must not prepare again") },
                    |_, _| async { panic!("cancelled initialization must not reconnect") },
                )
                .await,
                Err(DispatchError::NotAllowed)
            ));
            path.close();
        }
    }

    #[tokio::test]
    async fn fixed_udp_memory_all_direct_send_guards_reject_wrong_peer_without_io() {
        let peer = peer();
        let mut transport =
            DirectDatagramTransport::new(Dialer::default(), 1400, Default::default());
        transport.fixed_peer = Some(Path::new(peer).unwrap());
        assert!(!transport.supports_shared_destinations());
        let mut peers = vec!["192.0.2.1:443".parse().unwrap()];
        for (port, flow, scope) in [(444, 123, 7), (443, 124, 7), (443, 123, 8)] {
            peers.push(SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::1".parse().unwrap(),
                port,
                flow,
                scope,
            )));
        }
        for other in peers {
            assert!(matches!(
                transport.send(packet(other.into())).await,
                Err(DispatchError::NotAllowed)
            ));
            let returned = transport.send_owned(packet(other.into())).err().unwrap();
            assert_eq!(returned.remote, Destination::Ip(other));
            let batch = vec![packet(other.into()), packet(other.into())];
            let returned = transport.send_batch_owned(batch).err().unwrap();
            assert_eq!(returned.len(), 2);
            assert!(
                returned
                    .iter()
                    .all(|packet| packet.remote == Destination::Ip(other))
            );
        }
        assert!(
            transport
                .send(packet(Destination::domain("other.invalid", 443).unwrap()))
                .await
                .is_err()
        );
        assert!(
            transport.send_owned(packet(peer.into())).is_err(),
            "first exact peer is still unopened"
        );
        assert!(
            transport
                .send_batch_owned(vec![packet(peer.into()), packet(peer.into())])
                .is_err()
        );
        assert!(
            transport.sockets.is_empty(),
            "none of these guards may open a socket"
        );
        transport.close().await.unwrap();
        assert!(matches!(
            transport.send(packet(peer.into())).await,
            Err(DispatchError::NotAllowed)
        ));
        assert!(transport.sockets.is_empty());
    }

    #[tokio::test]
    async fn fixed_udp_memory_whole_datagram_helper_keeps_short_fatal_and_pending_drop() {
        for actual in [0, 4, 6] {
            let result = DirectDatagramTransport::finish_send(5, async { Ok(actual) }).await;
            assert!(
                matches!(result, Err(DispatchError::Other(value)) if value == "direct UDP socket truncated a datagram")
            );
        }
        DirectDatagramTransport::finish_send(5, async { Ok(5) })
            .await
            .unwrap();
        assert!(matches!(
            DirectDatagramTransport::finish_send(5, async {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            })
            .await,
            Err(DispatchError::NotAllowed)
        ));
        let drops = Arc::new(AtomicUsize::new(0));
        let held = Lease {
            token: 17,
            drops: drops.clone(),
        };
        let mut send = Box::pin(DirectDatagramTransport::finish_send(5, async move {
            let _held = held;
            std::future::pending::<std::io::Result<usize>>().await
        }));
        assert!(futures_util::poll!(send.as_mut()).is_pending());
        drop(send);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
