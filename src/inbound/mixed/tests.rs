//! Real frontend handlers over bounded memory IO; no host listener or peer.
use std::{collections::VecDeque, io, sync::Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;
use crate::{
    config::{ProxyAccess, ProxyCredentials},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    session::{DatagramSession, Destination, InboundKind, StreamSession},
};

#[derive(Default)]
struct Peers {
    streams: Mutex<VecDeque<DuplexStream>>,
    sessions: Mutex<Vec<StreamSession>>,
}

#[async_trait]
impl Dispatcher for Peers {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.sessions.lock().unwrap().push(session);
        self.streams
            .lock()
            .unwrap()
            .pop_front()
            .map(|stream| Box::new(stream) as BoxStream)
            .ok_or(DispatchError::ConnectionRefused)
    }

    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

fn connection(peers: Arc<Peers>, auth: Option<ProxyCredentials>) -> MixedConnection {
    let access = ProxyAccess {
        bind_address: None,
        allow_lan: true,
        ipv6: false,
    };
    let http = HttpServerConfig::proxy(1080, access, auth.clone()).unwrap();
    let socks = Socks5Handler::new(
        Socks5InboundConfig {
            tag: "mixed-in".into(),
            port: 1080,
            access,
            auth,
        },
        peers.clone(),
    );
    MixedConnection {
        access_rules: Default::default(),
        peer: "192.0.2.1:20000".parse().unwrap(),
        relay: "192.0.2.2:1080".parse().unwrap(),
        udp: None,
        http,
        socks,
        dispatcher: peers,
        cancellation: CancellationToken::new(),
        deadline: Instant::now() + HANDSHAKE_TIMEOUT,
    }
}

async fn exact(stream: &mut DuplexStream, expected: &[u8]) {
    let mut bytes = vec![0; expected.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, expected);
}

#[tokio::test]
async fn memory_mixed_protocols_preserve_first_byte_and_pipelined_tunnel_bytes_without_lan_auth() {
    for socks in [false, true] {
        let peers = Arc::new(Peers::default());
        let (upstream, mut remote) = tokio::io::duplex(1024);
        peers.streams.lock().unwrap().push_back(upstream);
        let connection = connection(peers.clone(), None);
        let (mut client, inbound) = tokio::io::duplex(1024);
        let task = tokio::spawn(connection.serve(inbound));
        let mut request = if socks {
            // Greeting, CONNECT and business bytes may arrive in one flight.
            vec![5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 3, 0, 80]
        } else {
            b"CONNECT 192.0.2.3:80 HTTP/1.1\r\nHost: 192.0.2.3:80\r\n\r\n".to_vec()
        };
        request.extend_from_slice(b"early-business");
        // Also exercise a first byte arriving separately from its handshake.
        client.write_all(&request[..1]).await.unwrap();
        tokio::task::yield_now().await;
        client.write_all(&request[1..]).await.unwrap();
        if socks {
            exact(&mut client, &[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        } else {
            exact(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        }
        exact(&mut remote, b"early-business").await;
        remote.write_all(b"response").await.unwrap();
        remote.shutdown().await.unwrap();
        exact(&mut client, b"response").await;
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let sessions = peers.sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].inbound,
            if socks {
                InboundKind::Socks5
            } else {
                InboundKind::Http
            }
        );
        assert_eq!(
            sessions[0].destination,
            Destination::Ip("192.0.2.3:80".parse().unwrap())
        );
    }
}

#[tokio::test]
async fn memory_mixed_authentication_failure_never_opens_upstream_or_switches_protocol() {
    for request in [
        b"CONNECT 192.0.2.3:80 HTTP/1.1\r\nHost: 192.0.2.3:80\r\n\r\n".as_slice(),
        &[5, 1, 0],
    ] {
        let peers = Arc::new(Peers::default());
        let connection = connection(
            peers.clone(),
            Some(ProxyCredentials::new("user", "password").unwrap()),
        );
        let (mut client, inbound) = tokio::io::duplex(1024);
        let task = tokio::spawn(connection.serve(inbound));
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        if request[0] == 5 {
            assert_eq!(response, [5, 0xff]);
        } else {
            assert!(response.starts_with(b"HTTP/1.1 407 "));
        }
        let _ = task.await.unwrap();
        assert!(peers.sessions.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn memory_mixed_cancellation_drops_both_active_tunnel_directions() {
    for socks in [false, true] {
        let peers = Arc::new(Peers::default());
        let (upstream, mut remote) = tokio::io::duplex(1024);
        peers.streams.lock().unwrap().push_back(upstream);
        let connection = connection(peers, None);
        let cancellation = connection.cancellation.clone();
        let (mut client, inbound) = tokio::io::duplex(1024);
        let task = tokio::spawn(connection.serve(inbound));
        if socks {
            client
                .write_all(&[5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 3, 0, 80])
                .await
                .unwrap();
            exact(&mut client, &[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        } else {
            client
                .write_all(b"CONNECT 192.0.2.3:80 HTTP/1.1\r\nHost: 192.0.2.3:80\r\n\r\n")
                .await
                .unwrap();
            exact(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        }
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        assert_eq!(remote.read(&mut byte).await.unwrap(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn memory_mixed_first_byte_and_protocol_handshake_share_one_deadline() {
    for first in [b'C', 5] {
        let peers = Arc::new(Peers::default());
        let connection = connection(peers.clone(), None);
        let (mut client, inbound) = tokio::io::duplex(1024);
        let task = tokio::spawn(connection.serve(inbound));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        client.write_all(&[first]).await.unwrap();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        if first == b'C' {
            assert!(response.starts_with(b"HTTP/1.1 408 "));
        } else {
            assert!(response.is_empty());
        }
        assert!(peers.sessions.lock().unwrap().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn memory_mixed_eof_and_cancellation_release_pending_protocol_reads() {
    for prefix in [b"".as_slice(), b"C", &[5]] {
        let peers = Arc::new(Peers::default());
        let connection = connection(peers.clone(), None);
        let cancellation = connection.cancellation.clone();
        let (mut client, inbound) = tokio::io::duplex(1024);
        let task = tokio::spawn(connection.serve(inbound));
        client.write_all(prefix).await.unwrap();
        tokio::task::yield_now().await;
        cancellation.cancel();
        task.await.unwrap().unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
        assert!(peers.sessions.lock().unwrap().is_empty());
    }
    for prefix in [b"".as_slice(), b"CON", &[5], &[4, 1, 0, 80]] {
        let peers = Arc::new(Peers::default());
        let connection = connection(peers.clone(), None);
        let (mut client, inbound) = tokio::io::duplex(1024);
        let task = tokio::spawn(connection.serve(inbound));
        client.write_all(prefix).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let result = task.await.unwrap();
        if prefix.is_empty() {
            result.unwrap();
            assert!(response.is_empty());
        } else {
            assert!(result.is_err());
            if prefix[0] != 5 {
                assert!(response.starts_with(b"HTTP/1.1 400 "));
            }
        }
        assert!(peers.sessions.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn memory_mixed_acl_multiple_users_and_auth_bypass() {
    for (skip, denied) in [(false, false), (true, false), (true, true)] {
        let yaml = format!(
            r#"mixed-port: 1080
allow-lan: true
bind-address: 192.0.2.2
authentication: [first:old, second:pass, first:new]
lan-allowed-ips: [192.0.2.0/24]
lan-disallowed-ips: [{}]
skip-auth-prefixes: [{}]
"#,
            if denied {
                "192.0.2.1/32"
            } else {
                "192.0.2.9/32"
            },
            if skip {
                "192.0.2.0/24"
            } else {
                "198.51.100.0/24"
            }
        );
        let config = crate::config::Config::parse_yaml(yaml.as_bytes()).unwrap();
        let crate::config::InboundConfig::Mixed(mixed) = &config.inbounds[0] else {
            panic!()
        };
        assert_eq!(
            mixed.access.bind_address,
            Some("192.0.2.2".parse().unwrap())
        );
        assert!(mixed.auth.as_ref().unwrap().matches(b"first", b"new"));
        assert!(!mixed.auth.as_ref().unwrap().matches(b"first", b"old"));
        let peers = Arc::new(Peers::default());
        let (upstream, mut remote) = tokio::io::duplex(1024);
        peers.streams.lock().unwrap().push_back(upstream);
        let mut connection = connection(peers.clone(), mixed.auth.clone());
        connection.access_rules = mixed.access_rules.clone();
        let cancellation = connection.cancellation.clone();
        let (mut client, inbound) = tokio::io::duplex(1024);
        let request = format!(
            "CONNECT 192.0.2.3:80 HTTP/1.1\r\nHost: 192.0.2.3:80\r\n{}\r\n",
            if skip {
                String::new()
            } else {
                format!(
                    "Proxy-Authorization: {}\r\n",
                    ProxyCredentials::new("second", "pass")
                        .unwrap()
                        .authorization_header_value()
                )
            }
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let task = tokio::spawn(connection.serve(inbound));
        if denied {
            assert!(task.await.unwrap().is_err());
            assert!(peers.sessions.lock().unwrap().is_empty());
        } else {
            exact(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
            client.write_all(b"body").await.unwrap();
            exact(&mut remote, b"body").await;
            cancellation.cancel();
            task.await.unwrap().unwrap();
        }
    }
}
