//! Fixed typed mocks for forwarding tests; no sockets, tasks or protocol credit.
use super::{
    DatagramBudget, DatagramTransport, DispatchError, TunPendingSend, TunSendOutcome, TunSendToken,
};
use crate::session::{Datagram, Destination};
use async_trait::async_trait;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
pub(crate) struct Probe {
    pub(crate) begins: AtomicUsize,
    pub(crate) finishes: AtomicUsize,
    pub(crate) legacy: AtomicUsize,
    pub(crate) closes: AtomicUsize,
    pub(crate) flow_id: Mutex<Option<Vec<u8>>>,
}

pub(crate) struct Packets {
    pub(crate) probe: Arc<Probe>,
    pub(crate) accept: bool,
    pub(crate) budget: DatagramBudget,
    completion: Option<TunSendToken>,
}

impl Packets {
    pub(crate) fn new(probe: Arc<Probe>) -> Self {
        Self {
            probe,
            accept: true,
            budget: DatagramBudget::new(u16::MAX, u16::MAX),
            completion: None,
        }
    }
}

#[async_trait]
impl DatagramTransport for Packets {
    fn supports_shared_destinations(&self) -> bool {
        false
    }
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        self.budget
    }

    fn try_begin_tun_send(
        &mut self,
        datagram: Datagram,
        flow_id: Option<&[u8]>,
    ) -> Result<TunPendingSend, Datagram> {
        self.probe.begins.fetch_add(1, Ordering::Relaxed);
        *self.probe.flow_id.lock().unwrap() = flow_id.map(<[u8]>::to_vec);
        if !self.accept || self.completion.is_some() {
            return Err(datagram);
        }
        let pending = TunPendingSend::new(Box::pin(async { Ok(()) }));
        self.completion = Some(pending.completion.clone());
        Ok(pending)
    }

    async fn finish_tun_send(
        &mut self,
        completion: TunSendToken,
        outcome: TunSendOutcome,
    ) -> Result<(), DispatchError> {
        let expected = self.completion.take().expect("one accepted operation");
        assert!(
            expected.same(&completion),
            "completion identity must be forwarded"
        );
        self.probe.finishes.fetch_add(1, Ordering::Relaxed);
        outcome.into_result()
    }

    async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
        self.probe.legacy.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        std::future::pending().await
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.probe.closes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

pub(crate) fn packet(payload: &'static [u8]) -> Datagram {
    Datagram {
        remote: Destination::Ip("192.0.2.1:443".parse().unwrap()),
        payload: bytes::Bytes::from_static(payload),
        sniffed_domain: Some("fixture.invalid".into()),
    }
}

pub(crate) fn assert_untouched(actual: Datagram, expected: &Datagram) {
    assert_eq!(actual.remote, expected.remote);
    assert_eq!(actual.sniffed_domain, expected.sniffed_domain);
    assert_eq!(actual.payload.as_ptr(), expected.payload.as_ptr());
    assert_eq!(actual.payload.len(), expected.payload.len());
}

pub(crate) async fn completion_outcomes(transport: &mut dyn DatagramTransport, probe: &Probe) {
    for case in 0..4 {
        let flow_id: Option<&[u8]> = (case % 2 == 0).then_some(b"opaque");
        let Ok(TunPendingSend {
            operation,
            completion,
        }) = transport.try_begin_tun_send(packet(b"ok"), flow_id)
        else {
            panic!("opened wrapper lost the owned-send capability");
        };
        assert_eq!(probe.flow_id.lock().unwrap().as_deref(), flow_id);
        operation.await.unwrap();
        let outcome = match case {
            0 => TunSendOutcome::Completed(Ok(())),
            1 => TunSendOutcome::Completed(Err(DispatchError::ConnectionRefused)),
            2 => TunSendOutcome::TimedOut,
            _ => TunSendOutcome::Cancelled,
        };
        let result = transport.finish_tun_send(completion, outcome).await;
        match case {
            0 => assert!(result.is_ok()),
            1 => assert!(matches!(result, Err(DispatchError::ConnectionRefused))),
            2 => assert!(matches!(result, Err(DispatchError::TimedOut))),
            _ => assert!(matches!(result, Err(DispatchError::NotAllowed))),
        }
    }
    assert_eq!(probe.begins.load(Ordering::Relaxed), 4);
    assert_eq!(probe.finishes.load(Ordering::Relaxed), 4);
    assert_eq!(probe.legacy.load(Ordering::Relaxed), 0);
}
