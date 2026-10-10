//! Structured TCP races: dropping the winner's scope cancels every loser.
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{future::Future, net::SocketAddr, time::Duration};
use tokio::time::{Instant, sleep_until};

pub(crate) async fn race_connections<T, E, F, C>(
    addresses: &[SocketAddr],
    prefer_v6: Option<bool>,
    connect: C,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    C: Fn(SocketAddr) -> F,
{
    assert!(!addresses.is_empty());
    let mut primary = addresses
        .iter()
        .filter(|a| prefer_v6.is_none_or(|v6| a.is_ipv6() == v6))
        .count();
    let mut attempts = addresses
        .iter()
        .map(|&address| {
            let attempt = connect(address);
            async move {
                (
                    prefer_v6.is_none_or(|v6| address.is_ipv6() == v6),
                    attempt.await,
                )
            }
        })
        .collect::<FuturesUnordered<_>>();
    let deadline = Instant::now() + Duration::from_millis(300);
    let mut fallback = None;
    let mut error = None;
    loop {
        if primary == 0
            && let Some(stream) = fallback.take()
        {
            return Ok(stream);
        }
        tokio::select! {
            biased;
            result = attempts.next() => match result {
                Some((is_primary, result)) => {
                    if is_primary { primary -= 1; }
                    match result {
                        Ok(stream) if is_primary => return Ok(stream),
                        Ok(stream) => { if fallback.is_none() { fallback = Some(stream); } }
                        Err(failed) => error = Some(failed),
                    }
                }
                None => return fallback.ok_or_else(|| error.expect("nonempty failed race")),
            },
            () = sleep_until(deadline), if fallback.is_some() => return Ok(fallback.take().expect("fallback ready")),
        }
    }
}

impl crate::config::ConnectionSettings {
    pub(crate) fn apply(self, socket: &socket2::SockRef<'_>) -> std::io::Result<()> {
        // Apply to accepted mixed connections as well as physical dials:
        // small proxy writes must not wait on Nagle and delayed ACKs.
        socket.set_tcp_nodelay(true)?;
        // Mihomo deliberately disables TCP probes on Android.
        if self.disable_keep_alive || cfg!(target_os = "android") {
            return socket.set_keepalive(false);
        }
        socket.set_keepalive(true)?;
        let mut options = socket2::TcpKeepalive::new();
        if self.keep_alive_idle >= 0 {
            options = options.with_time(Duration::from_secs(if self.keep_alive_idle == 0 {
                15
            } else {
                self.keep_alive_idle as u64
            }));
        }
        if self.keep_alive_interval >= 0 {
            options =
                options.with_interval(Duration::from_secs(if self.keep_alive_interval == 0 {
                    15
                } else {
                    self.keep_alive_interval as u64
                }));
        }
        // Old Windows 10 releases lack TCP_KEEPCNT; retain their OS count.
        #[cfg(not(windows))]
        {
            options = options.with_retries(9);
        }
        socket.set_tcp_keepalive(&options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    #[tokio::test(start_paused = true)]
    async fn concurrent_dial_cancels_losers_and_honors_family_preference() {
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let closed = Arc::new(AtomicUsize::new(0));
        let addresses = [
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ];
        let start = Instant::now();
        let result = race_connections(&addresses, Some(true), |a| {
            let guard = Guard(closed.clone());
            async move {
                let _guard = guard;
                if a.is_ipv6() {
                    std::future::pending::<()>().await;
                }
                Ok::<_, ()>(a)
            }
        })
        .await
        .unwrap();
        assert_eq!(result, addresses[0]);
        assert_eq!(start.elapsed(), Duration::from_millis(300));
        assert_eq!(closed.load(Ordering::Relaxed), 2);
        // This creates no peer or listener: inspect only an unconnected socket.
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        let options = crate::config::ConnectionSettings {
            keep_alive_idle: 42,
            keep_alive_interval: 7,
            ..Default::default()
        };
        options.apply(&socket2::SockRef::from(&socket)).unwrap();
        assert!(socket.tcp_nodelay().unwrap());
        assert_eq!(socket.keepalive().unwrap(), !cfg!(target_os = "android"));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert_eq!(
                socket.tcp_keepalive_time().unwrap(),
                Duration::from_secs(42)
            );
            assert_eq!(
                socket.tcp_keepalive_interval().unwrap(),
                Duration::from_secs(7)
            );
        }
        crate::config::ConnectionSettings {
            disable_keep_alive: true,
            ..options
        }
        .apply(&socket2::SockRef::from(&socket))
        .unwrap();
        assert!(socket.tcp_nodelay().unwrap());
        assert!(!socket.keepalive().unwrap());
    }
}
