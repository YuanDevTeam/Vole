//! Per-runtime filtering around the host's subscriber; no process-wide level.

use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    level_filters::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use crate::config::LogLevel;
use tracing_core::span::Current;

pub(crate) fn dispatch(level: LogLevel) -> Dispatch {
    let level = match level {
        LogLevel::Silent => LevelFilter::OFF,
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warning => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
    };
    Dispatch::new(Filtered {
        inner: tracing::dispatcher::get_default(Clone::clone),
        level,
    })
}

struct Filtered {
    inner: Dispatch,
    level: LevelFilter,
}

impl Subscriber for Filtered {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= self.level && self.inner.enabled(metadata)
    }
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if *metadata.level() <= self.level {
            self.inner.register_callsite(metadata)
        } else {
            Interest::never()
        }
    }
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(self.level)
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
        if self.enabled(event.metadata()) {
            self.inner.event(event);
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
            (LogLevel::Silent, 0),
            (LogLevel::Debug, 4),
        ] {
            let count = Arc::new(AtomicUsize::new(0));
            let host = Dispatch::new(Counter(count.clone()));
            let filtered = tracing::dispatcher::with_default(&host, || dispatch(level));
            async {
                crate::resources::observation::spawn(async {
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
}
