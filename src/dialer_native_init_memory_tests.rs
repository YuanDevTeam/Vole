//! No FD, native syscall, thread, blocking job, listener or network is created.
use super::*;
use crate::resources::observation::ResourceProbe;
use std::{future::Future, task::Poll};

#[test]
fn typed_admission_bounds_cancelled_waiters_and_waits_for_stop() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let probe = ResourceProbe::default();
    runtime.block_on(probe.scope(async {
        let initialization = SocketInitialization::default();
        let mut admitted = Vec::new();
        for _ in 0..MAX_SOCKET_INITIALIZATIONS {
            admitted.push(initialization.admit_native_socket().await.unwrap());
        }
        assert_eq!(initialization.tasks.len(), MAX_SOCKET_INITIALIZATIONS);
        assert_eq!(initialization.submissions.available_permits(), 0);

        let mut caller = Box::pin(initialization.admit_native_socket());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(caller.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        // Cancel an actual queued admission, not merely a borrowed Pin/wait.
        drop(caller);
        assert_eq!(initialization.tasks.len(), MAX_SOCKET_INITIALIZATIONS);
        assert_eq!(initialization.submissions.available_permits(), 0);

        initialization.begin_shutdown();
        assert_eq!(
            admitted[0].check().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(initialization.admit_native_socket().await.is_err());
        let mut stop = Box::pin(initialization.shutdown());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        // Cancel/drop each admitted caller: the real tracker must prevent Stop
        // completion until the last registered guard, not just the last wait.
        while admitted.len() > 1 {
            drop(admitted.pop());
        }
        assert_eq!(initialization.tasks.len(), 1);
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(admitted);
        stop.await;
        assert_eq!(initialization.tasks.len(), 0);
        assert!(initialization.admit_native_socket().await.is_err());
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    }));
}
