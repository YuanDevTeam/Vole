use super::*;
use futures_util::FutureExt as _;

#[test]
fn pending_write_and_flush_notifications_match_target_contract() {
    for flush in [false, true] {
        assert_pending_notification(flush);
    }
}

fn assert_pending_notification(flush: bool) {
    let notify = Arc::new(Notify::new());
    let handle = Arc::new(TcpStreamHandle::new(8, 8, notify.clone()));
    let mut stream = TcpStream::new(
        FlowKey {
            source: "192.0.2.1:12000".parse().unwrap(),
            destination: "198.51.100.1:443".parse().unwrap(),
        },
        handle.clone(),
    );
    let mut context = Context::from_waker(std::task::Waker::noop());
    let published = matches!(
        Pin::new(&mut stream).poll_write(&mut context, b"accepted"),
        Poll::Ready(Ok(8))
    );
    let legitimate_permit = notify.notified().now_or_never().is_some();
    let initially_empty = notify.notified().now_or_never().is_none();
    let mut pending = [false; 4];
    let mut extra_permits = [false; 4];
    for index in 0..pending.len() {
        pending[index] = if flush {
            Pin::new(&mut stream).poll_flush(&mut context).is_pending()
        } else {
            Pin::new(&mut stream)
                .poll_write(&mut context, b"later")
                .is_pending()
        };
        extra_permits[index] = notify.notified().now_or_never().is_some();
    }
    let unchanged = handle.app_send.len() == 8;
    // No task, socket or driver exists in this test. Retire the real handle
    // before the semantic assertion, including the expected old-Mac failure.
    handle.mark_stopped();
    drop(stream);
    drop(handle);
    drop(notify);
    assert!(published && legitimate_permit && initially_empty && unchanged);
    assert_eq!(pending, [true; 4]);
    assert_eq!(
        extra_permits,
        [cfg!(not(target_vendor = "apple")); 4],
        "still-Pending polls published no new state; Apple targets suppress redundant notifications"
    );
}
