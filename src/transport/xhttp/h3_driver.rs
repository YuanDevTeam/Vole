//! HTTP/3 over the shared controlled datagram seam. No socket or DNS fallback.
use super::{ConnectionGuard, DriverOwner, SendRequest, connection_closed};
use crate::transport::{quic::OwnedRuntime, quiche_h3};
use std::{io, sync::Arc, time::Duration};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

pub(crate) use quiche_h3::Transport as QuicTransport;
#[derive(Clone, Debug)]
pub(super) struct Sender {
    pub requests: quiche_h3::Client,
    pub runtime: Arc<OwnedRuntime>,
    #[cfg(feature = "interop-test")]
    pub observation: quiche_h3::Client,
}
pub(super) async fn connect(
    raw: QuicTransport,
    keepalive: i32,
    owner: &DriverOwner,
) -> io::Result<(SendRequest, Arc<ConnectionGuard>)> {
    let cancel = owner.cancellation.child_token();
    let stop = cancel.clone();
    let (ready, response) = oneshot::channel();
    let guard = owner.spawn_managed(async move {
        let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
        let options = quiche_h3::Options {
            stream_window: crate::limits::XHTTP_H3_STREAM_WINDOW as u64,
            connection_window: crate::limits::XHTTP_H3_CONNECTION_WINDOW as u64,
            headers: u64::from(super::MAX_H2_HEADER_LIST_SIZE),
            idle: Duration::from_secs(300),
            keepalive: (keepalive >= 0).then(|| Duration::from_secs(if keepalive == 0 { 10 } else { keepalive as u64 })),
            ..Default::default()
        };
        match quiche_h3::Driver::new(raw, options).await {
            Ok((requests, driver)) => {
                let driver_cancel = CancellationToken::new();
                let driver = driver.run(driver_cancel.clone());
                tokio::pin!(driver);
                let mut finished = false;
                let result = tokio::select! {biased;
                    () = stop.cancelled() => Err(connection_closed()),
                    _ = &mut driver => { finished = true; Err(connection_closed()) },
                    result = requests.ready(false) => result,
                };
                match result {
                    Ok(()) => {
                        let sent = ready.send(Ok(Sender { #[cfg(feature = "interop-test")] observation: requests.clone(), requests, runtime: runtime.clone() }));
                        if sent.is_ok() { tokio::select! {biased; () = stop.cancelled() => {}, _ = &mut driver => { finished = true; } } }
                    },
                    Err(error) => { let _ = ready.send(Err(error)); },
                }
                driver_cancel.cancel();
                if !finished { let _ = driver.await; }
            },
            Err(error) => { let _ = ready.send(Err(error)); },
        }
        runtime.stop().await;
    }, cancel)?;
    let sender = response.await.map_err(|_| connection_closed())??;
    Ok((SendRequest::H3(sender), Arc::new(guard)))
}
pub(super) fn failure(_: impl std::fmt::Display) -> io::Error {
    io::Error::other("XHTTP HTTP/3 exchange failed")
}
