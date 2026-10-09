//! Wire fixtures use independent head/body readers and bounded duplex peers.
use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream},
    net::TcpStream,
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::{HttpBasicAuth, HttpServer, HttpServerConfig};
use crate::{
    config::ProxyAccess,
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    session::{DatagramSession, Destination, StreamSession},
};

const WAIT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Peers {
    streams: Mutex<VecDeque<DuplexStream>>,
    targets: Mutex<Vec<Destination>>,
}

#[async_trait]
impl Dispatcher for Peers {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.targets.lock().unwrap().push(session.destination);
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

struct Fixture {
    address: SocketAddr,
    peers: Arc<Peers>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl Fixture {
    async fn start(
        count: usize,
        mut configure: impl FnMut(&mut HttpServerConfig),
    ) -> (Self, Vec<BufReader<DuplexStream>>) {
        let peers = Arc::new(Peers::default());
        let remotes = (0..count)
            .map(|_| {
                let (local, remote) = tokio::io::duplex(4096);
                peers.streams.lock().unwrap().push_back(local);
                BufReader::new(remote)
            })
            .collect();
        let mut config = HttpServerConfig::proxy(
            0,
            ProxyAccess {
                bind_address: None,
                allow_lan: false,
                ipv6: false,
            },
            Some(auth()),
        )
        .unwrap();
        configure(&mut config);
        let server = HttpServer::bind(config, peers.clone()).await.unwrap();
        let address = server.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(server.serve(cancellation.clone()));
        (
            Self {
                address,
                peers,
                cancellation,
                task: Some(task),
            },
            remotes,
        )
    }

    async fn client(&self) -> BufReader<TcpStream> {
        BufReader::new(
            TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, self.address.port()))
                .await
                .unwrap(),
        )
    }

    async fn stop(mut self) {
        self.cancellation.cancel();
        timeout(WAIT, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(std::net::TcpListener::bind(self.address).unwrap());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn auth() -> HttpBasicAuth {
    HttpBasicAuth::new("fixture", "password").unwrap()
}

fn request(method: &str, target: &str, fields: &str) -> String {
    format!(
        "{method} {target} HTTP/1.1\r\nHost: fixture.invalid\r\nProxy-Authorization: {}\r\n{fields}\r\n",
        auth().authorization_header_value()
    )
}

async fn head<R: AsyncBufRead + Unpin>(stream: &mut R) -> String {
    let mut result = String::new();
    loop {
        let mut line = String::new();
        assert!(
            timeout(WAIT, stream.read_line(&mut line))
                .await
                .unwrap()
                .unwrap()
                > 0,
            "truncated head: {result}"
        );
        result.push_str(&line);
        assert!(result.len() <= 32768);
        if line == "\r\n" {
            return result;
        }
    }
}

async fn exact<R: AsyncReadExt + Unpin>(stream: &mut R, expected: &[u8]) {
    let mut bytes = vec![0; expected.len()];
    timeout(WAIT, stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, expected);
}

async fn eof<R: AsyncReadExt + Unpin>(stream: &mut R) {
    let mut byte = [0];
    assert_eq!(
        timeout(WAIT, stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn local_no_auth_and_shared_auth_work_on_both_loopback_families() {
    let ipv6_available = match crate::inbound::listen::bind_tcp("[::1]:0".parse().unwrap()) {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(error) if crate::inbound::listen::address_family_unavailable(&error) => false,
        Err(error) => panic!("{error}"),
    };
    for shared in [false, true] {
        let (fixture, _remotes) = Fixture::start(2, |config| {
            *config = HttpServerConfig::proxy(
                0,
                ProxyAccess {
                    bind_address: None,
                    allow_lan: shared,
                    ipv6: true,
                },
                shared.then(auth),
            )
            .unwrap();
        })
        .await;
        if shared {
            for authorization in ["", "Proxy-Authorization: Basic d3Jvbmc6d3Jvbmc=\r\n"] {
                let mut client = fixture.client().await;
                client.write_all(format!("CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test\r\n{authorization}\r\n").as_bytes()).await.unwrap();
                assert!(head(&mut client).await.starts_with("HTTP/1.1 407"));
            }
            assert!(fixture.peers.targets.lock().unwrap().is_empty());
        }
        let mut addresses = vec![SocketAddr::from(([127, 0, 0, 1], fixture.address.port()))];
        if ipv6_available {
            addresses.push(SocketAddr::from((
                std::net::Ipv6Addr::LOCALHOST,
                fixture.address.port(),
            )));
        }
        for address in addresses {
            let mut client = BufReader::new(TcpStream::connect(address).await.unwrap());
            let wire = if shared {
                request("CONNECT", "origin.test:443", "")
            } else {
                "CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test\r\n\r\n".to_owned()
            };
            client.write_all(wire.as_bytes()).await.unwrap();
            assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
        }
        assert_eq!(
            fixture.peers.targets.lock().unwrap().len(),
            if ipv6_available { 2 } else { 1 }
        );
        fixture.stop().await;
    }
}

#[tokio::test]
async fn malformed_or_truncated_bodies_cannot_be_reinterpreted_as_another_request() {
    for (framing, body) in [
        ("Content-Length: 20\r\n", "short"),
        ("Transfer-Encoding: chunked\r\n", "2\r\nx"),
        (
            "Transfer-Encoding: chunked\r\n",
            "x\r\nGET http://next.test/ HTTP/1.1\r\nHost: next.test\r\n\r\n",
        ),
        (
            "Transfer-Encoding: chunked\r\n",
            "0\r\nProxy-Authorization: private\r\n\r\n",
        ),
    ] {
        let (fixture, _remotes) = Fixture::start(1, |_| {}).await;
        let mut client = fixture.client().await;
        client
            .write_all(
                format!("{}{body}", request("POST", "http://origin.test/", framing)).as_bytes(),
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        assert!(head(&mut client).await.starts_with("HTTP/1.1 400"));
        eof(&mut client).await;
        assert_eq!(fixture.peers.targets.lock().unwrap().len(), 1);
        fixture.stop().await;
    }
}

#[tokio::test]
async fn pipeline_routes_and_authenticates_every_request_without_credential_leaks() {
    let (fixture, mut remotes) = Fixture::start(2, |_| {}).await;
    let mut second = remotes.pop().unwrap();
    let mut first = remotes.pop().unwrap();
    let mut client = fixture.client().await;
    let wire = format!(
        "{}abc{}GET http://three.test/ HTTP/1.1\r\nHost: three.test\r\n\r\n",
        request(
            "POST",
            "http://one.test/upload",
            "Content-Length: 3\r\nX-Vole-Measure-Diagnostic: v1\r\nConnection: X-Private\r\nX-Private: secret\r\n"
        ),
        request("GET", "http://two.test/next", "")
    );
    timeout(WAIT, async {
        tokio::join!(
            async {
                client.write_all(wire.as_bytes()).await.unwrap();
                for body in [b"one", b"two"] {
                    assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
                    exact(&mut client, body).await;
                }
                assert!(head(&mut client).await.starts_with("HTTP/1.1 407"));
                eof(&mut client).await;
            },
            async {
                let forwarded = head(&mut first).await.to_ascii_lowercase();
                assert!(forwarded.starts_with("post /upload http/1.1\r\n"));
                for secret in ["proxy-authorization", "x-vole", "x-private", "password"] {
                    assert!(!forwarded.contains(secret));
                }
                exact(&mut first, b"abc").await;
                first
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
                    .await
                    .unwrap();
                let forwarded = head(&mut second).await;
                assert!(forwarded.starts_with("GET /next HTTP/1.1"));
                second
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo")
                    .await
                    .unwrap();
            }
        );
    })
    .await
    .unwrap();
    assert_eq!(
        *fixture.peers.targets.lock().unwrap(),
        [
            Destination::domain("one.test", 80).unwrap(),
            Destination::domain("two.test", 80).unwrap()
        ]
    );
    fixture.stop().await;
}

#[tokio::test]
async fn keep_alive_requests_reenter_the_real_rule_dispatcher() {
    use crate::{
        config::Config,
        routing::{EmptyGeoMatcher, ProxyDispatchers, RoutingDispatcher, RuleSet},
    };
    let first = Arc::new(Peers::default());
    let second = Arc::new(Peers::default());
    let mut remotes = Vec::new();
    for peers in [&first, &second] {
        let (local, remote) = tokio::io::duplex(4096);
        peers.streams.lock().unwrap().push_back(local);
        remotes.push(BufReader::new(remote));
    }
    let config = Config::parse_yaml(b"mixed-port: 1080\nproxies:\n  - {name: first, type: socks5, server: 192.0.2.1, port: 1080}\n  - {name: second, type: socks5, server: 192.0.2.2, port: 1080}\nrules: ['DOMAIN,one.test,first', 'MATCH,second']\n").unwrap();
    let router = RoutingDispatcher::new(
        ProxyDispatchers::new(vec![first.clone(), second.clone()]).unwrap(),
        Arc::new(Peers::default()),
        None,
        RuleSet::compile(config.rules).unwrap(),
        Arc::new(EmptyGeoMatcher),
    );
    let config = HttpServerConfig::proxy(
        0,
        ProxyAccess {
            bind_address: None,
            allow_lan: false,
            ipv6: false,
        },
        Some(auth()),
    )
    .unwrap();
    let server = HttpServer::bind(config, Arc::new(router)).await.unwrap();
    let cancellation = CancellationToken::new();
    let fixture = Fixture {
        address: server.local_addr().unwrap(),
        peers: first.clone(),
        task: Some(tokio::spawn(server.serve(cancellation.clone()))),
        cancellation,
    };
    let mut client = fixture.client().await;
    timeout(WAIT, async {
        tokio::join!(
            async {
                for domain in ["one.test", "two.test"] {
                    client
                        .write_all(request("GET", &format!("http://{domain}/"), "").as_bytes())
                        .await
                        .unwrap();
                }
                for marker in [b"one", b"two"] {
                    assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
                    exact(&mut client, marker).await;
                }
            },
            async {
                for (mut remote, marker) in remotes.into_iter().zip(["one", "two"]) {
                    head(&mut remote).await;
                    remote
                        .write_all(
                            format!("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{marker}")
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
            }
        );
    })
    .await
    .unwrap();
    assert_eq!(
        *first.targets.lock().unwrap(),
        [Destination::domain("one.test", 80).unwrap()]
    );
    assert_eq!(
        *second.targets.lock().unwrap(),
        [Destination::domain("two.test", 80).unwrap()]
    );
    fixture.stop().await;
}

#[tokio::test]
async fn chunk_extensions_trailers_and_pipeline_keep_separate_boundaries() {
    let (fixture, mut remotes) = Fixture::start(1, |_| {}).await;
    let mut remote = remotes.pop().unwrap();
    let mut client = fixture.client().await;
    timeout(WAIT, async {
        tokio::join!(async {
            client.write_all(format!("{}3 ; kind = \"a;b\"\r\nabc\r\n0\r\nX-Checksum: yes\r\n\r\nGET http://next.test/ HTTP/1.1\r\nHost: next.test\r\n\r\n", request("POST", "http://origin.test/", "Transfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n")).as_bytes()).await.unwrap();
            let response = head(&mut client).await;
            assert!(response.contains("Transfer-Encoding: chunked\r\n"));
            assert!(!response.to_ascii_lowercase().contains("x-vole"));
            exact(&mut client, b"2\r\nok\r\n0\r\nX-Checksum: yes\r\n\r\n").await;
            assert!(head(&mut client).await.starts_with("HTTP/1.1 407"));
        }, async {
            assert!(head(&mut remote).await.contains("Trailer: X-Checksum\r\n"));
            exact(&mut remote, b"3\r\nabc\r\n0\r\nX-Checksum: yes\r\n\r\n").await;
            remote.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nX-Vole-Measure-Diagnostic: private\r\n\r\n2;ignored=value\r\nok\r\n0\r\nX-Checksum: yes\r\n\r\n").await.unwrap();
        });
    }).await.unwrap();
    assert_eq!(fixture.peers.targets.lock().unwrap().len(), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn head_informational_204_304_and_eof_responses_have_correct_boundaries() {
    let (fixture, remotes) = Fixture::start(4, |_| {}).await;
    let mut client = fixture.client().await;
    let responses: [&[u8]; 4] = [
        b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n",
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 456\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\neof-body",
    ];
    timeout(WAIT, async {
        tokio::join!(
            async {
                for method in ["HEAD", "GET", "GET", "GET"] {
                    client
                        .write_all(request(method, "http://origin.test/", "").as_bytes())
                        .await
                        .unwrap();
                }
                for status in [200, 103, 204, 304, 200] {
                    assert!(
                        head(&mut client)
                            .await
                            .starts_with(&format!("HTTP/1.1 {status}"))
                    );
                }
                exact(&mut client, b"eof-body").await;
                eof(&mut client).await;
            },
            async {
                for (mut remote, response) in remotes.into_iter().zip(responses) {
                    head(&mut remote).await;
                    remote.write_all(response).await.unwrap();
                    remote.shutdown().await.unwrap();
                }
            }
        );
    })
    .await
    .unwrap();
    fixture.stop().await;
}

#[tokio::test]
async fn expect_continue_and_early_final_do_not_deadlock_or_reuse_unread_body() {
    for early in [false, true] {
        let (fixture, mut remotes) = Fixture::start(1, |_| {}).await;
        let mut remote = remotes.pop().unwrap();
        let mut client = fixture.client().await;
        timeout(WAIT, async {
            tokio::join!(async {
                client.write_all(request("POST", "http://origin.test/", "Expect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n").as_bytes()).await.unwrap();
                if !early {
                    assert!(head(&mut client).await.starts_with("HTTP/1.1 100"));
                    client.write_all(b"body").await.unwrap();
                }
                assert!(head(&mut client).await.starts_with(if early { "HTTP/1.1 413" } else { "HTTP/1.1 200" }));
                eof(&mut client).await;
            }, async {
                assert!(head(&mut remote).await.contains("Expect: 100-continue"));
                if !early {
                    remote.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.unwrap();
                    exact(&mut remote, b"body").await;
                }
                remote.write_all(if early { b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n" } else { b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" }).await.unwrap();
            });
        }).await.unwrap();
        fixture.stop().await;
    }
}

#[tokio::test]
async fn websocket_upgrade_preserves_both_sides_early_bytes_and_half_close() {
    let (fixture, mut remotes) = Fixture::start(1, |_| {}).await;
    let mut remote = remotes.pop().unwrap();
    let mut client = fixture.client().await;
    timeout(WAIT, async {
        tokio::join!(async {
            client.write_all(format!("{}early", request("GET", "http://origin.test/ws", "Connection: Upgrade\r\nUpgrade: websocket\r\n")).as_bytes()).await.unwrap();
            let response = head(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 101"));
            assert!(response.contains("Upgrade: websocket\r\n"));
            exact(&mut client, b"hello").await;
            exact(&mut client, b"early").await;
            client.write_all(b"late").await.unwrap();
            client.shutdown().await.unwrap();
            exact(&mut client, b"late").await;
            eof(&mut client).await;
        }, async {
            assert!(head(&mut remote).await.contains("Upgrade: websocket\r\n"));
            remote.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello").await.unwrap();
            let (mut read, mut write) = tokio::io::split(remote);
            tokio::io::copy(&mut read, &mut write).await.unwrap();
            write.shutdown().await.unwrap();
        });
    }).await.unwrap();
    fixture.stop().await;
}

#[tokio::test]
async fn rejected_upgrade_is_a_response_but_unsolicited_or_wrong_101_fails_closed() {
    for (upgrade, response, status) in [
        (
            true,
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno",
            403,
        ),
        (
            true,
            "HTTP/1.1 101 Switching\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
            502,
        ),
        (
            false,
            "HTTP/1.1 101 Switching\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            502,
        ),
    ] {
        let (fixture, mut remotes) = Fixture::start(1, |_| {}).await;
        let mut remote = remotes.pop().unwrap();
        let mut client = fixture.client().await;
        timeout(WAIT, async {
            tokio::join!(
                async {
                    let fields = if upgrade {
                        "Connection: close, Upgrade\r\nUpgrade: websocket\r\n"
                    } else {
                        "Connection: close\r\n"
                    };
                    client
                        .write_all(request("GET", "http://origin.test/", fields).as_bytes())
                        .await
                        .unwrap();
                    assert!(
                        head(&mut client)
                            .await
                            .starts_with(&format!("HTTP/1.1 {status}"))
                    );
                    if status == 403 {
                        exact(&mut client, b"no").await;
                    }
                    eof(&mut client).await;
                },
                async {
                    head(&mut remote).await;
                    remote.write_all(response.as_bytes()).await.unwrap();
                }
            );
        })
        .await
        .unwrap();
        fixture.stop().await;
    }
}

#[tokio::test]
async fn malformed_heads_fail_before_dispatch_and_slow_heads_are_bounded() {
    let (fixture, _) = Fixture::start(0, |config| {
        config.header_limit = 1024;
        config.header_timeout = Duration::from_millis(200);
    })
    .await;
    for fields in [
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Content-Length: +1\r\n",
        "Host: duplicate\r\n",
        "Connection: Content-Length\r\n",
        " Bad-Fold: value\r\n",
        "Upgrade: websocket\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: Proxy-Authorization\r\n",
    ] {
        let mut client = fixture.client().await;
        client
            .write_all(request("POST", "http://origin.test/", fields).as_bytes())
            .await
            .unwrap();
        assert!(
            head(&mut client).await.starts_with("HTTP/1.1 400"),
            "{fields}"
        );
        eof(&mut client).await;
    }
    let mut client = fixture.client().await;
    client
        .write_all(
            request(
                "GET",
                "http://origin.test/",
                &format!("X-Long: {}\r\n", "x".repeat(1100)),
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(head(&mut client).await.starts_with("HTTP/1.1 431"));
    let mut client = fixture.client().await;
    client.write_all(b"GET ").await.unwrap();
    assert!(head(&mut client).await.starts_with("HTTP/1.1 408"));
    assert!(fixture.peers.targets.lock().unwrap().is_empty());
    fixture.stop().await;
}

#[tokio::test]
async fn ambiguous_upstream_framing_is_never_forwarded_and_legacy_chunked_is_decoded() {
    for legacy in [false, true] {
        let (fixture, mut remotes) = Fixture::start(1, |_| {}).await;
        let mut remote = remotes.pop().unwrap();
        let mut client = fixture.client().await;
        timeout(WAIT, async {
            tokio::join!(async {
                let mut wire = request("GET", "http://origin.test/", "Connection: keep-alive\r\n");
                if legacy { wire = wire.replace("HTTP/1.1", "HTTP/1.0"); }
                client.write_all(wire.as_bytes()).await.unwrap();
                let response = head(&mut client).await;
                assert!(response.starts_with(if legacy { "HTTP/1.0 200" } else { "HTTP/1.1 502" }));
                if legacy {
                    assert!(!response.to_ascii_lowercase().contains("transfer-encoding"));
                    exact(&mut client, b"ok").await;
                }
                eof(&mut client).await;
            }, async {
                head(&mut remote).await;
                remote.write_all(if legacy { b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n" } else { b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n" }).await.unwrap();
            });
        }).await.unwrap();
        fixture.stop().await;
    }
}

#[tokio::test]
async fn stop_joins_idle_body_connect_and_upgrade_handlers_and_releases_ports() {
    for kind in ["header", "body", "connect", "upgrade"] {
        let (fixture, mut remotes) = Fixture::start(1, |_| {}).await;
        let mut client = fixture.client().await;
        let mut remote = remotes.pop().unwrap();
        match kind {
            "header" => client.write_all(b"G").await.unwrap(),
            "body" => {
                client
                    .write_all(
                        request("POST", "http://origin.test/", "Content-Length: 100000\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                head(&mut remote).await;
            }
            "connect" => {
                client
                    .write_all(request("CONNECT", "origin.test:443", "").as_bytes())
                    .await
                    .unwrap();
                assert!(head(&mut client).await.starts_with("HTTP/1.1 200"));
            }
            _ => {
                client
                    .write_all(
                        request(
                            "GET",
                            "http://origin.test/",
                            "Connection: Upgrade\r\nUpgrade: websocket\r\n",
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                head(&mut remote).await;
                remote.write_all(b"HTTP/1.1 101 Switching\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
                assert!(head(&mut client).await.starts_with("HTTP/1.1 101"));
            }
        }
        fixture.stop().await;
        let mut byte = [0];
        match timeout(WAIT, client.read(&mut byte)).await.unwrap() {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("connection survived stop: {other:?}"),
        }
    }
}

#[tokio::test]
async fn fixed_and_chunked_ten_mib_bodies_stream_in_both_directions_with_matching_hashes() {
    const BLOCK: [u8; 8192] = [0x5a; 8192];
    const COUNT: usize = 1280;
    let mut expected = Sha256::new();
    for _ in 0..COUNT {
        expected.update(BLOCK);
    }
    let expected = finish_sha256(expected);
    for chunked in [false, true] {
        let (fixture, mut remotes) = Fixture::start(1, |_| {}).await;
        let mut remote = remotes.pop().unwrap();
        let mut client = fixture.client().await;
        let framing = if chunked {
            "Transfer-Encoding: chunked\r\n".to_owned()
        } else {
            format!("Content-Length: {}\r\n", BLOCK.len() * COUNT)
        };
        timeout(Duration::from_secs(30), async {
            tokio::join!(
                async {
                    client
                        .write_all(
                            request(
                                "POST",
                                "http://origin.test/",
                                &format!("{framing}Connection: close\r\n"),
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                    send_large(&mut client, chunked, &BLOCK, COUNT).await;
                    let response = head(&mut client).await;
                    assert!(response.contains(&format!("X-Upload-SHA256: {expected}\r\n")));
                    assert_eq!(
                        receive_large(&mut client, chunked, BLOCK.len() * COUNT).await,
                        expected
                    );
                    eof(&mut client).await;
                },
                async {
                    head(&mut remote).await;
                    assert_eq!(
                        receive_large(&mut remote, chunked, BLOCK.len() * COUNT).await,
                        expected
                    );
                    remote
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\n{framing}X-Upload-SHA256: {expected}\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                    send_large(&mut remote, chunked, &BLOCK, COUNT).await;
                }
            );
        })
        .await
        .unwrap();
        fixture.stop().await;
    }
}

async fn send_large<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    chunked: bool,
    block: &[u8],
    count: usize,
) {
    for _ in 0..count {
        if chunked {
            writer
                .write_all(format!("{:x}\r\n", block.len()).as_bytes())
                .await
                .unwrap();
        }
        writer.write_all(block).await.unwrap();
        if chunked {
            writer.write_all(b"\r\n").await.unwrap();
        }
    }
    if chunked {
        writer.write_all(b"0\r\n\r\n").await.unwrap();
    }
}

async fn receive_large<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    chunked: bool,
    expected_length: usize,
) -> String {
    let mut remaining = expected_length;
    let mut hash = Sha256::new();
    let mut buffer = [0; 4096];
    loop {
        let size = if chunked {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            usize::from_str_radix(line.trim_end(), 16).unwrap()
        } else {
            remaining
        };
        if size == 0 {
            if chunked {
                exact(reader, b"\r\n").await;
            }
            break;
        }
        assert!(size <= remaining);
        let mut left = size;
        while left > 0 {
            let length = left.min(buffer.len());
            reader.read_exact(&mut buffer[..length]).await.unwrap();
            hash.update(&buffer[..length]);
            left -= length;
        }
        remaining -= size;
        if chunked {
            exact(reader, b"\r\n").await;
        }
    }
    assert_eq!(remaining, 0);
    finish_sha256(hash)
}

fn finish_sha256(hash: Sha256) -> String {
    use std::fmt::Write as _;

    let mut hex = String::with_capacity(64);
    for byte in hash.finalize() {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}
