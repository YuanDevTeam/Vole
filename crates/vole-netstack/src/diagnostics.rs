//! Default-off, integer-only observations for an explicitly observed passive stack.
//! The callback is synchronous, nonblocking and must not panic or perform I/O.

/// One completed driver pass or one selected normal wait result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverObservation {
    DrivePass {
        tcp_entry_visits: u64,
        app_rx_bytes: u64,
        app_tx_bytes: u64,
        /// No app bytes moved and no packet emitted; protocol state may progress.
        no_data_progress: bool,
    },
    WaitIngress,
    WaitNotify,
    WaitTimer,
}

/// A plain function pointer, carrying no traffic, task, queue or runtime owner.
pub type DriverObserver = fn(DriverObservation);
