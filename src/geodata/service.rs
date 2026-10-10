//! Long-lived GeoData update scheduling.
//!
//! The service is attached to a running instance, but the manager and its
//! cross-process lock own the shared resource state. Network traffic is sent
//! through the shared runtime route dispatcher.

use std::{
    io,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use tokio_util::sync::CancellationToken;

use super::{GeoDataKind, GeoDataManager, GeoDataManagerError, manager::GeoDataRegistrationLease};
use crate::{
    config::GeoDataUrls,
    dispatch::Dispatcher,
    resource::http::{
        DEFAULT_DOWNLOAD_TIMEOUT, DownloadOutcome, DownloadRequest, HttpOptions, download,
    },
};

const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(15);
const MIN_LOOP_DELAY: Duration = Duration::from_secs(1);
const UPDATE_BUSY_RETRY: Duration = Duration::from_secs(5);
const RETRY_BACKOFF: [Duration; 4] = [
    Duration::from_secs(60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
];

pub(crate) struct GeoDataUpdateService {
    manager: Arc<GeoDataManager>,
    dispatcher: Arc<dyn Dispatcher>,
    registration: GeoDataRegistrationLease,
    urls: GeoDataUrls,
    options: HttpOptions,
    etag_support: bool,
    auto_update: bool,
}

impl GeoDataUpdateService {
    #[must_use]
    pub(crate) fn new(
        manager: Arc<GeoDataManager>,
        dispatcher: Arc<dyn Dispatcher>,
        registration: GeoDataRegistrationLease,
        urls: GeoDataUrls,
        user_agent: String,
        etag_support: bool,
        auto_update: bool,
    ) -> Self {
        Self {
            manager,
            dispatcher,
            registration,
            urls,
            options: HttpOptions {
                user_agent,
                ..HttpOptions::default()
            },
            etag_support,
            auto_update,
        }
    }

    #[cfg(test)]
    pub(crate) fn urls(&self) -> &GeoDataUrls {
        &self.urls
    }

    /// Runs until cancelled. GeoData failures are recorded and retried but
    /// never terminate the business data plane.
    pub(crate) async fn run(self, cancellation: CancellationToken) -> io::Result<()> {
        let mut retries = RetryState::default();
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }

            match self.due_resources(cancellation.clone()).await {
                Ok(due) => {
                    retries.clear_expired_not_due(&due, Instant::now());
                    for kind in due {
                        if cancellation.is_cancelled() {
                            return Ok(());
                        }
                        if !retries.ready(kind, Instant::now()) {
                            continue;
                        }
                        match self.update_one(kind, cancellation.clone()).await {
                            Ok(UpdateAttempt::Completed) => retries.succeeded(kind),
                            Ok(UpdateAttempt::Busy) => {
                                retries.defer(kind, UPDATE_BUSY_RETRY);
                            }
                            Err(_) if cancellation.is_cancelled() => return Ok(()),
                            Err(error) => {
                                let delay = retries.failed(kind);
                                tracing::warn!(
                                    geodata_kind = %kind,
                                    retry_seconds = delay.as_secs(),
                                    error = %error,
                                    "Vole GeoData update failed; business routing remains active"
                                );
                            }
                        }
                    }
                }
                Err(_) if cancellation.is_cancelled() => return Ok(()),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "Vole GeoData state check failed; business routing remains active"
                    );
                }
            }

            let delay = retries
                .next_delay(Instant::now())
                .unwrap_or(STATUS_POLL_INTERVAL)
                .min(STATUS_POLL_INTERVAL)
                .max(MIN_LOOP_DELAY);
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    async fn due_resources(
        &self,
        cancellation: CancellationToken,
    ) -> Result<Vec<GeoDataKind>, String> {
        let manager = self.manager.clone();
        let registration = self.registration.clone();
        let urls = self.urls.clone();
        let auto_update = self.auto_update;
        blocking_operation(move || {
            let due = manager.due_resources_for_active_registration_with_cancellation(
                &registration,
                [
                    (GeoDataKind::GeoSite, urls.geosite.as_str()),
                    (GeoDataKind::GeoIp, urls.geoip.as_str()),
                ],
                SystemTime::now(),
                &cancellation,
            )?;
            if auto_update {
                return Ok(due);
            }
            let status = manager.status_for_active_registration(&registration, &cancellation)?;
            Ok(due
                .into_iter()
                .filter(|kind| {
                    status
                        .as_ref()
                        .is_some_and(|status| !status.resource(*kind).available)
                })
                .collect())
        })
        .await?
        .map_err(|error: GeoDataManagerError| error.to_string())
    }

    async fn update_one(
        &self,
        kind: GeoDataKind,
        cancellation: CancellationToken,
    ) -> Result<UpdateAttempt, String> {
        let source_url = resource_url(&self.urls, kind).to_owned();
        let manager = self.manager.clone();
        let registration = self.registration.clone();
        let begin_source = source_url.clone();
        let begin_cancellation = cancellation.clone();
        let session = match blocking_operation(move || {
            manager.begin_update_for_active_registration_with_cancellation(
                &registration,
                kind,
                &begin_source,
                SystemTime::now(),
                &begin_cancellation,
            )
        })
        .await?
        {
            Ok(Some(session)) => session,
            Ok(None) => return Ok(UpdateAttempt::Completed),
            Err(GeoDataManagerError::UpdateBusy) => return Ok(UpdateAttempt::Busy),
            Err(error) => return Err(error.to_string()),
        };
        let etag = self
            .etag_support
            .then(|| session.request_etag().map(ToOwned::to_owned))
            .flatten();
        let request = DownloadRequest {
            dispatcher: self.dispatcher.clone(),
            url: source_url,
            etag: etag.clone(),
            temporary_path: session.temporary_path().to_path_buf(),
            timeout: DEFAULT_DOWNLOAD_TIMEOUT,
            cancellation: cancellation.clone(),
            options: self.options.clone(),
        };
        match download(request).await {
            Ok(DownloadOutcome::NotModified { .. }) => {
                blocking_operation(move || {
                    session.not_modified_with_cancellation(etag, &cancellation)
                })
                .await?
                .map_err(|error| error.to_string())?;
                tracing::info!(geodata_kind = %kind, "Vole GeoData is current");
                Ok(UpdateAttempt::Completed)
            }
            Ok(DownloadOutcome::Downloaded {
                etag, sha256, size, ..
            }) => {
                let report = blocking_operation(move || {
                    session.commit_with_cancellation(etag, sha256, size, &cancellation)
                })
                .await?
                .map_err(|error| error.to_string())?;
                tracing::info!(
                    geodata_kind = %kind,
                    bytes = size,
                    active_registration = report.active_registration,
                    "Vole GeoData downloaded and hot-activated"
                );
                Ok(UpdateAttempt::Completed)
            }
            Err(error) => {
                let message = error.to_string();
                let failure = message.clone();
                if let Err(cleanup_error) = blocking_operation(move || session.fail(failure))
                    .await
                    .and_then(|result| result.map_err(|error| error.to_string()))
                {
                    return Err(format!("{message}; state cleanup failed: {cleanup_error}"));
                }
                Err(message)
            }
        }
    }
}

/// Always join management work, including during cancellation. Dropping a
/// blocking task's handle would let it outlive the runtime's stop barrier.
async fn blocking_operation<T: Send + 'static>(
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| "GeoData management task failed".to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateAttempt {
    Completed,
    Busy,
}

#[derive(Debug, Clone, Copy, Default)]
struct RetrySlot {
    failures: usize,
    retry_at: Option<Instant>,
}

#[derive(Debug, Default)]
struct RetryState {
    geosite: RetrySlot,
    geoip: RetrySlot,
}

impl RetryState {
    fn slot(&self, kind: GeoDataKind) -> &RetrySlot {
        match kind {
            GeoDataKind::GeoSite => &self.geosite,
            GeoDataKind::GeoIp => &self.geoip,
        }
    }

    fn slot_mut(&mut self, kind: GeoDataKind) -> &mut RetrySlot {
        match kind {
            GeoDataKind::GeoSite => &mut self.geosite,
            GeoDataKind::GeoIp => &mut self.geoip,
        }
    }

    fn ready(&self, kind: GeoDataKind, now: Instant) -> bool {
        self.slot(kind)
            .retry_at
            .is_none_or(|retry_at| retry_at <= now)
    }

    fn succeeded(&mut self, kind: GeoDataKind) {
        *self.slot_mut(kind) = RetrySlot::default();
    }

    fn defer(&mut self, kind: GeoDataKind, delay: Duration) {
        self.slot_mut(kind).retry_at = Some(Instant::now() + delay);
    }

    fn failed(&mut self, kind: GeoDataKind) -> Duration {
        let slot = self.slot_mut(kind);
        let delay = RETRY_BACKOFF[slot.failures.min(RETRY_BACKOFF.len() - 1)];
        slot.failures = slot.failures.saturating_add(1);
        slot.retry_at = Some(Instant::now() + delay);
        delay
    }

    fn next_delay(&self, now: Instant) -> Option<Duration> {
        [self.geosite.retry_at, self.geoip.retry_at]
            .into_iter()
            .flatten()
            .map(|retry_at| retry_at.saturating_duration_since(now))
            .min()
    }

    fn clear_expired_not_due(&mut self, due: &[GeoDataKind], now: Instant) {
        for kind in [GeoDataKind::GeoSite, GeoDataKind::GeoIp] {
            if !due.contains(&kind)
                && self
                    .slot(kind)
                    .retry_at
                    .is_some_and(|retry_at| retry_at <= now)
            {
                self.succeeded(kind);
            }
        }
    }
}

fn resource_url(urls: &GeoDataUrls, kind: GeoDataKind) -> &str {
    match kind {
        GeoDataKind::GeoSite => &urls.geosite,
        GeoDataKind::GeoIp => &urls.geoip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{RuleAction, RuleKind, RuleSpec},
        dispatch::{BoxStream, DatagramTransport, DispatchError},
        geodata::{GEOSITE_FILE_NAME, GeoRequirements},
        routing::GeoMatcher,
        session::{DatagramSession, StreamSession},
    };

    struct NoNetworkDispatcher;

    #[async_trait::async_trait]
    impl Dispatcher for NoNetworkDispatcher {
        async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
            panic!("GeoData drain regression must not connect to a network peer");
        }

        async fn open_datagram(
            &self,
            _: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            panic!("GeoData drain regression must not open a datagram transport");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_joins_external_reload_without_blocking_the_async_worker_or_publishing_late() {
        use sha2::{Digest, Sha256};
        use std::{fs, io::Write};

        let root = tempfile::tempdir().unwrap();
        let old_asset = b"\x0a\x15\x0a\x02cn\x12\x0f\x08\x02\x12\x0bold.example";
        let new_asset = b"\x0a\x15\x0a\x02cn\x12\x0f\x08\x02\x12\x0bnew.example";
        let manager = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        fs::write(root.path().join(GEOSITE_FILE_NAME), old_asset).unwrap();
        let registration = manager
            .register(
                GeoRequirements::collect(
                    &[RuleSpec {
                        kind: RuleKind::GeoSite("cn".to_owned()),
                        action: RuleAction::Direct,
                        no_resolve: false,
                    }],
                    &[],
                )
                .unwrap(),
            )
            .unwrap();
        let matcher = registration.matcher();
        let old = matcher.snapshot();
        assert!(old.matches_geosite("cn", "www.old.example"));

        let external = GeoDataManager::open(root.path(), Duration::from_secs(60)).unwrap();
        let update = external.begin_update(GeoDataKind::GeoSite).unwrap();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(update.temporary_path())
            .unwrap();
        file.write_all(new_asset).unwrap();
        file.sync_all().unwrap();
        drop(file);
        update
            .commit(
                None,
                Sha256::digest(new_asset).into(),
                new_asset.len() as u64,
            )
            .unwrap();

        let cancellation = CancellationToken::new();
        let service = GeoDataUpdateService::new(
            manager,
            Arc::new(NoNetworkDispatcher),
            registration.updater_lease(),
            GeoDataUrls {
                geoip: "https://rules.example.test/geoip.dat".to_owned(),
                geosite: "https://rules.example.test/geosite.dat".to_owned(),
            },
            "fixture".into(),
            true,
            true,
        );
        let run = tokio::spawn(service.run(cancellation.clone()));
        tokio::time::timeout(Duration::from_secs(1), async {
            while matcher.geosite_available("cn") {
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        })
        .await
        .expect("GeoData drain must leave the current-thread async worker responsive");
        assert!(!run.is_finished());
        assert!(old.matches_geosite("cn", "www.old.example"));

        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("Stop must cancel and join the pending GeoData drain")
            .unwrap()
            .unwrap();
        drop(old);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!matcher.geosite_available("cn"));
        assert!(!matcher.matches_geosite("cn", "www.new.example"));
    }

    #[test]
    fn retry_backoff_is_bounded_and_resets_after_success() {
        let mut retries = RetryState::default();
        assert_eq!(
            (0..5)
                .map(|_| retries.failed(GeoDataKind::GeoSite))
                .collect::<Vec<_>>(),
            [
                RETRY_BACKOFF[0],
                RETRY_BACKOFF[1],
                RETRY_BACKOFF[2],
                RETRY_BACKOFF[3],
                RETRY_BACKOFF[3],
            ]
        );
        retries.succeeded(GeoDataKind::GeoSite);
        assert_eq!(retries.slot(GeoDataKind::GeoSite).failures, 0);
        assert!(retries.slot(GeoDataKind::GeoSite).retry_at.is_none());
    }

    #[test]
    fn resources_use_configured_urls() {
        let urls = GeoDataUrls {
            geoip: "https://rules.example.test/custom-geoip".to_owned(),
            geosite: "https://rules.example.test/custom-geosite".to_owned(),
        };
        assert_eq!(
            resource_url(&urls, GeoDataKind::GeoSite),
            "https://rules.example.test/custom-geosite"
        );
        assert_eq!(
            resource_url(&urls, GeoDataKind::GeoIp),
            "https://rules.example.test/custom-geoip"
        );
    }

    #[test]
    fn expired_retry_for_a_resource_no_longer_due_is_cleared() {
        let mut retries = RetryState::default();
        retries.slot_mut(GeoDataKind::GeoIp).retry_at = Some(Instant::now());
        retries.clear_expired_not_due(&[GeoDataKind::GeoSite], Instant::now());
        assert!(retries.slot(GeoDataKind::GeoIp).retry_at.is_none());
    }
}
