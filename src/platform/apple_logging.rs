//! Bounded Apple Unified Logging sink for Vole tracing events.
//!
//! Vole is a library embedded in both the app and Packet Tunnel Extension, so
//! it must not install a process-global tracing subscriber. Each public Invoke
//! scope and each Vole runtime thread enters the shared dispatcher instead.

use std::{
    fmt::{self, Write as _},
    sync::{
        Mutex, Once, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use oslog::{Level as OsLogLevel, OsLog};
use tracing::{
    Dispatch, Event, Level, Metadata, Subscriber,
    field::{Field, Visit},
    level_filters::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

const SUBSYSTEM: &str = "io.github.yuandevteam.vole";
const CATEGORY: &str = "vole";
const MAX_EVENT_BYTES: usize = 2 * 1024;
const TRUNCATION_MARKER: &str = "...";
const DEBUG_EVENT_WINDOW: Duration = Duration::from_secs(1);
const DEBUG_EVENT_BUDGET: u32 = 64;
// Xcode may omit lower transport levels from Packet Tunnel Extensions.
// The message carries the original tracing level on every Apple platform.
const TRANSPORT_LEVEL: OsLogLevel = OsLogLevel::Error;

static DISPATCH: OnceLock<Dispatch> = OnceLock::new();
static ANNOUNCED: Once = Once::new();

/// Routes tracing events on the current thread to Apple Unified Logging until
/// the returned guard is dropped. This restores any host default afterward
/// rather than claiming tracing's process-global slot.
pub(crate) fn enter() -> tracing::dispatcher::DefaultGuard {
    let dispatch = DISPATCH.get_or_init(|| Dispatch::new(AppleLogSubscriber::new()));
    let guard = tracing::dispatcher::set_default(dispatch);
    ANNOUNCED.call_once(|| {
        tracing::info!(target: "vole", "Apple Unified Logging enabled");
    });
    guard
}

struct AppleLogSubscriber {
    log: OsLog,
    debug_events: DebugRateLimiter,
    next_span_id: AtomicU64,
}

impl AppleLogSubscriber {
    fn new() -> Self {
        Self {
            log: OsLog::new(SUBSYSTEM, CATEGORY),
            debug_events: DebugRateLimiter::new(),
            next_span_id: AtomicU64::new(1),
        }
    }

    fn accepts(metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && is_vole_target(metadata.target())
    }
}

impl Subscriber for AppleLogSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        Self::accepts(metadata) && self.log.level_is_enabled(TRANSPORT_LEVEL)
    }

    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if Self::accepts(metadata) {
            // Apple can change enabled log types while the process is running,
            // so consult `enabled` for every event instead of caching `always`.
            Interest::sometimes()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        // Span callsites are rejected by `accepts`. A host subscriber can keep
        // a global callsite interested, however, so return unique IDs without
        // retaining any corresponding span state.
        loop {
            let id = self.next_span_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return Id::from_u64(id);
            }
        }
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        if !self.enabled(metadata) {
            return;
        }
        if matches!(*metadata.level(), Level::TRACE | Level::DEBUG) {
            match self.debug_events.admit() {
                DebugAdmission::Allow { suppressed } => {
                    if suppressed != 0 {
                        let mut summary = FixedBuffer::new();
                        let _ = write!(
                            summary,
                            "[DEBUG] vole: suppressed_debug_events={suppressed}"
                        );
                        self.log.with_level(TRANSPORT_LEVEL, summary.as_str());
                    }
                }
                DebugAdmission::Deny => return,
            }
        }

        let mut output = FixedBuffer::new();
        let _ = write!(output, "[{}] {}: ", metadata.level(), metadata.target());
        event.record(&mut EventVisitor::new(&mut output));
        self.log.with_level(TRANSPORT_LEVEL, output.as_str());
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebugAdmission {
    Allow { suppressed: u64 },
    Deny,
}

struct DebugRateLimiter {
    state: Mutex<DebugWindow>,
}

struct DebugWindow {
    started: Instant,
    emitted: u32,
    suppressed: u64,
}

impl DebugRateLimiter {
    fn new() -> Self {
        Self {
            state: Mutex::new(DebugWindow {
                started: Instant::now(),
                emitted: 0,
                suppressed: 0,
            }),
        }
    }

    fn admit(&self) -> DebugAdmission {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        if now.duration_since(state.started) >= DEBUG_EVENT_WINDOW {
            let suppressed = state.suppressed;
            state.started = now;
            state.emitted = 1;
            state.suppressed = 0;
            return DebugAdmission::Allow { suppressed };
        }
        if state.emitted < DEBUG_EVENT_BUDGET {
            state.emitted += 1;
            DebugAdmission::Allow { suppressed: 0 }
        } else {
            state.suppressed = state.suppressed.saturating_add(1);
            DebugAdmission::Deny
        }
    }
}

fn is_vole_target(target: &str) -> bool {
    target == "vole"
        || target.starts_with("vole::")
        || target == "vole_netstack"
        || target.starts_with("vole_netstack::")
}

struct EventVisitor<'a> {
    output: &'a mut FixedBuffer,
    has_field: bool,
}

impl<'a> EventVisitor<'a> {
    fn new(output: &'a mut FixedBuffer) -> Self {
        Self {
            output,
            has_field: false,
        }
    }

    fn separator(&mut self) {
        if self.has_field {
            let _ = self.output.write_char(' ');
        }
        self.has_field = true;
    }
}

impl Visit for EventVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.separator();
        if field.name() == "message" {
            let _ = self.output.write_str(value);
        } else {
            let _ = write!(self.output, "{}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.separator();
        if field.name() == "message" {
            let _ = write!(self.output, "{value:?}");
        } else {
            let _ = write!(self.output, "{}={value:?}", field.name());
        }
    }
}

struct FixedBuffer {
    bytes: [u8; MAX_EVENT_BYTES],
    len: usize,
    truncated: bool,
}

impl FixedBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_EVENT_BYTES],
            len: 0,
            truncated: false,
        }
    }

    fn as_str(&self) -> &str {
        // Every write copies complete UTF-8 scalar values or ASCII literals.
        unsafe { std::str::from_utf8_unchecked(&self.bytes[..self.len]) }
    }

    fn push(&mut self, text: &str) {
        if self.truncated {
            return;
        }
        let payload_limit = MAX_EVENT_BYTES - TRUNCATION_MARKER.len();
        if self.len + text.len() > payload_limit {
            self.bytes[self.len..self.len + TRUNCATION_MARKER.len()]
                .copy_from_slice(TRUNCATION_MARKER.as_bytes());
            self.len += TRUNCATION_MARKER.len();
            self.truncated = true;
            return;
        }
        self.bytes[self.len..self.len + text.len()].copy_from_slice(text.as_bytes());
        self.len += text.len();
    }
}

impl fmt::Write for FixedBuffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for character in value.chars() {
            if character == '\0' {
                self.push("\\0");
            } else {
                let mut encoded = [0_u8; 4];
                self.push(character.encode_utf8(&mut encoded));
            }
            if self.truncated {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_is_bounded_and_utf8_safe() {
        let mut buffer = FixedBuffer::new();
        let oversized = "你".repeat(MAX_EVENT_BYTES);
        buffer.write_str(&oversized).unwrap();

        assert!(buffer.as_str().is_char_boundary(buffer.as_str().len()));
        assert!(buffer.as_str().len() <= MAX_EVENT_BYTES);
        assert!(buffer.as_str().ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn buffer_removes_interior_nul() {
        let mut buffer = FixedBuffer::new();
        buffer.write_str("before\0after").unwrap();
        assert_eq!(buffer.as_str(), "before\\0after");
    }

    #[test]
    fn target_filter_excludes_host_and_dependency_events() {
        assert!(is_vole_target("vole::tun_runtime"));
        assert!(is_vole_target("vole_netstack::tcp"));
        assert!(!is_vole_target("host-application"));
        assert!(!is_vole_target("h2"));
    }

    #[test]
    fn debug_rate_limiter_has_a_fixed_budget_and_reports_suppression() {
        let limiter = DebugRateLimiter::new();
        for _ in 0..DEBUG_EVENT_BUDGET {
            assert_eq!(limiter.admit(), DebugAdmission::Allow { suppressed: 0 });
        }
        assert_eq!(limiter.admit(), DebugAdmission::Deny);

        {
            let mut state = limiter.state.lock().unwrap();
            state.started = Instant::now() - DEBUG_EVENT_WINDOW;
        }
        assert_eq!(limiter.admit(), DebugAdmission::Allow { suppressed: 1 });
    }
}
