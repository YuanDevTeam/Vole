//! Bounded, request-local path labels. No addresses, questions or credentials.
use std::{future::Future, sync::Mutex};
tokio::task_local! { static TRACE: Mutex<Vec<&'static str>>; }
pub(crate) fn record(step: &'static str) {
    let _ = TRACE.try_with(|trace| {
        let mut trace = trace.lock().unwrap();
        if trace.len() < 32 {
            trace.push(step);
        }
    });
}
pub(crate) fn snapshot() -> Vec<&'static str> {
    TRACE
        .try_with(|trace| trace.lock().unwrap().clone())
        .unwrap_or_default()
}
pub(crate) async fn capture<T>(future: impl Future<Output = T>) -> (T, Vec<&'static str>) {
    TRACE
        .scope(Mutex::new(Vec::new()), async {
            let result = future.await;
            (result, snapshot())
        })
        .await
}
