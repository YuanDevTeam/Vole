//! Session-local levels and complete event payloads with bounded subscriptions.

use crate::config::LogLevel;
use std::{
    fmt::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};
use tokio::sync::broadcast;
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    level_filters::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};
use tracing_core::span::Current;

const LOG_CAPACITY: usize = 64;

pub(crate) fn dispatch(level: LogLevel) -> Dispatch {
    let (inner, logs) = tracing::dispatcher::get_default(|current| {
        if let Some(filtered) = current.downcast_ref::<Filtered>() {
            (filtered.inner.clone(), filtered.logs.clone())
        } else {
            (current.clone(), Arc::new(RuntimeLog::new(level)))
        }
    });
    Dispatch::new(Filtered { inner, logs })
}

pub(crate) fn current() -> Option<Arc<RuntimeLog>> {
    tracing::dispatcher::get_default(|current| {
        current.downcast_ref::<Filtered>().map(|f| f.logs.clone())
    })
}

fn number(level: LogLevel) -> u8 {
    match level {
        LogLevel::Silent => 0,
        LogLevel::Error => 1,
        LogLevel::Warning => 2,
        LogLevel::Info => 3,
        LogLevel::Debug => 4,
    }
}
fn event_number(level: &tracing::Level) -> u8 {
    match *level {
        tracing::Level::ERROR => 1,
        tracing::Level::WARN => 2,
        tracing::Level::INFO => 3,
        _ => 4,
    }
}
pub(crate) struct RuntimeLog {
    level: AtomicU8,
    channel: Mutex<Option<broadcast::Sender<Arc<LogEvent>>>>,
}
impl RuntimeLog {
    pub(crate) fn new(level: LogLevel) -> Self {
        let logs = Self {
            level: AtomicU8::new(0),
            channel: Mutex::new(None),
        };
        logs.set_level(level);
        logs
    }
    pub(crate) fn set_level(&self, level: LogLevel) {
        self.level.store(number(level), Ordering::Relaxed);
    }
    pub(crate) fn level(&self) -> LogLevel {
        match self.level.load(Ordering::Relaxed) {
            0 => LogLevel::Silent,
            1 => LogLevel::Error,
            2 => LogLevel::Warning,
            3 => LogLevel::Info,
            _ => LogLevel::Debug,
        }
    }
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        event_number(metadata.level()) <= number(self.level())
    }
    fn has_subscribers(&self) -> bool {
        self.channel
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|sender| sender.receiver_count() != 0)
    }
    pub(crate) fn subscribe(self: &Arc<Self>) -> LogSubscription {
        let mut channel = self.channel.lock().unwrap();
        let receiver = channel
            .get_or_insert_with(|| broadcast::channel(LOG_CAPACITY).0)
            .subscribe();
        LogSubscription {
            logs: self.clone(),
            receiver: Some(receiver),
        }
    }
    fn event(&self, event: &Event<'_>) {
        if !self.has_subscribers() {
            return;
        }
        let value = Arc::new(LogEvent {
            level: event_number(event.metadata().level()),
            payload: format_event(event),
            time: time::OffsetDateTime::now_utc(),
        });
        if let Some(sender) = self.channel.lock().unwrap().as_ref() {
            let _ = sender.send(value);
        }
    }
}
pub(crate) struct LogSubscription {
    logs: Arc<RuntimeLog>,
    receiver: Option<broadcast::Receiver<Arc<LogEvent>>>,
}
impl LogSubscription {
    pub(crate) async fn recv(&mut self) -> Option<Arc<LogEvent>> {
        loop {
            match self.receiver.as_mut()?.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}
impl Drop for LogSubscription {
    fn drop(&mut self) {
        self.receiver.take();
        let mut channel = self.logs.channel.lock().unwrap();
        if channel
            .as_ref()
            .is_some_and(|sender| sender.receiver_count() == 0)
        {
            *channel = None;
        }
    }
}
pub(crate) struct LogEvent {
    level: u8,
    payload: String,
    time: time::OffsetDateTime,
}
impl LogEvent {
    pub(crate) fn matches(&self, level: LogLevel) -> bool {
        self.level <= number(level)
    }
    pub(crate) fn json(&self, structured: bool) -> serde_json::Value {
        let level = match self.level {
            1 => "error",
            2 => "warning",
            3 => "info",
            _ => "debug",
        };
        if structured {
            serde_json::json!({"time":format!("{:02}:{:02}:{:02}",self.time.hour(),self.time.minute(),self.time.second()),"level":if level == "warning" { "warn" } else { level },"message":self.payload,"fields":[]})
        } else {
            serde_json::json!({"type":level,"payload":self.payload})
        }
    }
}
pub(crate) fn format_event(event: &Event<'_>) -> String {
    let mut fields = EventFields {
        payload: event.metadata().target().to_owned(),
    };
    event.record(&mut fields);
    fields.payload
}

struct EventFields {
    payload: String,
}
impl Visit for EventFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        let _ = write!(self.payload, " {}={value}", field.name());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.payload, " {}={value:?}", field.name());
    }
}
struct Filtered {
    inner: Dispatch,
    logs: Arc<RuntimeLog>,
}
impl Subscriber for Filtered {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.logs.enabled(metadata) && (self.inner.enabled(metadata) || self.logs.has_subscribers())
    }
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        let _ = self.inner.register_callsite(metadata);
        Interest::sometimes()
    }
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }
    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        self.inner.new_span(attrs)
    }
    fn record(&self, span: &Id, values: &Record<'_>) {
        self.inner.record(span, values);
    }
    fn record_follows_from(&self, span: &Id, follows: &Id) {
        self.inner.record_follows_from(span, follows);
    }
    fn event(&self, event: &Event<'_>) {
        if self.logs.enabled(event.metadata()) {
            if self.inner.enabled(event.metadata()) {
                self.inner.event(event);
            }
            self.logs.event(event);
        }
    }
    fn enter(&self, span: &Id) {
        self.inner.enter(span);
    }
    fn exit(&self, span: &Id) {
        self.inner.exit(span);
    }
    fn clone_span(&self, span: &Id) -> Id {
        self.inner.clone_span(span)
    }
    fn try_close(&self, span: Id) -> bool {
        self.inner.try_close(span)
    }
    fn current_span(&self) -> Current {
        self.inner.current_span()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tracing::instrument::WithSubscriber;

    struct Counter(Arc<AtomicUsize>);
    impl Subscriber for Counter {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, _: &Event<'_>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    #[tokio::test]
    async fn runtime_level_follows_spawned_work_without_changing_host_logging() {
        for (level, expected) in [
            (LogLevel::Info, 3),
            (LogLevel::Warning, 2),
            (LogLevel::Error, 1),
            (LogLevel::Silent, 0),
            (LogLevel::Debug, 5),
        ] {
            let count = Arc::new(AtomicUsize::new(0));
            let host = Dispatch::new(Counter(count.clone()));
            let filtered = tracing::dispatcher::with_default(&host, || dispatch(level));
            async {
                crate::resources::observation::spawn(async {
                    tracing::trace!(target:"external", "trace");
                    tracing::debug!("debug");
                    tracing::info!("info");
                    tracing::warn!("warning");
                    tracing::error!("error");
                })
                .await
                .unwrap();
            }
            .with_subscriber(filtered)
            .await;
            assert_eq!(count.load(Ordering::Relaxed), expected);
            tracing::dispatcher::with_default(&host, || {
                tracing::debug!("host logging remains active")
            });
            assert_eq!(count.load(Ordering::Relaxed), expected + 1);
        }
    }

    #[test]
    fn controller_without_subscribers_does_not_format_event_fields() {
        struct FormattingProbe(Arc<AtomicUsize>);
        impl std::fmt::Debug for FormattingProbe {
            fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fetch_add(1, Ordering::Relaxed);
                output.write_str("synthetic field")
            }
        }
        let formats = Arc::new(AtomicUsize::new(0));
        let host_events = Arc::new(AtomicUsize::new(0));
        let logs = Arc::new(RuntimeLog::new(LogLevel::Info));
        let filtered = Dispatch::new(Filtered {
            inner: Dispatch::new(Counter(host_events.clone())),
            logs: logs.clone(),
        });
        tracing::dispatcher::with_default(&filtered, || {
            tracing::info!(target: "external", data = ?FormattingProbe(formats.clone()));
        });
        assert_eq!(host_events.load(Ordering::Relaxed), 1);
        assert_eq!(formats.load(Ordering::Relaxed), 0);
        assert!(logs.channel.lock().unwrap().is_none());
    }

    #[test]
    fn controller_logs_preserve_complete_events_without_content_or_rate_filters() {
        let logs = Arc::new(RuntimeLog::new(LogLevel::Info));
        let filtered = Dispatch::new(Filtered {
            inner: Dispatch::none(),
            logs: logs.clone(),
        });
        assert!(!logs.has_subscribers());
        tracing::dispatcher::with_default(&filtered, || {
            tracing::info!(target:"vole::controller", bytes=1, secret="never-publish", "private target");
        });
        assert!(logs.channel.lock().unwrap().is_none());
        let mut subscription = logs.subscribe();
        const TARGET: &str = concat!(
            "external::",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
        );
        let message = "完整信息😀\n\t".repeat(200);
        let error = std::io::Error::other("synthetic error details");
        tracing::dispatcher::with_default(&filtered, || {
            tracing::info!(target: TARGET,
                bytes = 17_u64,
                unknown_count = -9_i64,
                ratio = 1.25_f64,
                active = true,
                destination = "synthetic.invalid",
                token = "synthetic-token",
                details = ?vec![1, 2, 3],
                error = &error as &(dyn std::error::Error + 'static),
                "{message}"
            );
        });
        let event = subscription.receiver.as_mut().unwrap().try_recv().unwrap();
        let value = event.json(false);
        let payload = value["payload"].as_str().unwrap();
        assert!(payload.starts_with(TARGET));
        for content in [
            "bytes=17",
            "unknown_count=-9",
            "ratio=1.25",
            "active=true",
            "synthetic.invalid",
            "synthetic-token",
            "[1, 2, 3]",
            "synthetic error details",
            "destination",
            "error",
        ] {
            assert!(payload.contains(content), "missing {content}");
        }
        assert!(payload.contains(&message));
        assert_eq!(event.json(true)["message"], payload);
        logs.set_level(LogLevel::Error);
        tracing::dispatcher::with_default(
            &filtered,
            || tracing::info!(target:"vole::controller",bytes=3),
        );
        assert!(subscription.receiver.as_mut().unwrap().try_recv().is_err());
        logs.set_level(LogLevel::Debug);
        tracing::dispatcher::with_default(
            &filtered,
            || tracing::debug!(target:"vole::controller",bytes=4),
        );
        assert!(
            subscription
                .receiver
                .as_mut()
                .unwrap()
                .try_recv()
                .unwrap()
                .payload
                .contains("bytes=4")
        );
        for _ in 0..128 {
            tracing::dispatcher::with_default(
                &filtered,
                || tracing::info!(target:"external",bytes=1),
            );
            assert!(subscription.receiver.as_mut().unwrap().try_recv().is_ok());
        }
        for _ in 0..128 {
            tracing::dispatcher::with_default(
                &filtered,
                || tracing::info!(target:"external",bytes=1),
            );
        }
        assert_eq!(
            logs.channel.lock().unwrap().as_ref().unwrap().len(),
            LOG_CAPACITY
        );
        assert!(matches!(
            subscription.receiver.as_mut().unwrap().try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(64))
        ));
        drop(subscription);
        assert!(logs.channel.lock().unwrap().is_none());
    }

    #[test]
    fn nested_runtime_dispatch_reuses_one_log_bus_and_mutable_filter() {
        let filtered = dispatch(LogLevel::Warning);
        let first = tracing::dispatcher::with_default(&filtered, || current().unwrap());
        let nested = tracing::dispatcher::with_default(&filtered, || dispatch(LogLevel::Debug));
        let next = tracing::dispatcher::with_default(&nested, || current().unwrap());
        assert!(Arc::ptr_eq(&first, &next));
        assert_eq!(next.level(), LogLevel::Warning);
        next.set_level(LogLevel::Debug);
        assert_eq!(first.level(), LogLevel::Debug);
    }
}
