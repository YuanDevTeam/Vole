use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

use crate::{
    Packet,
    pmtu::PathMtuHint,
    segmentation::{PathMtu, PendingSegments, is_pure_tcp_ack, reverse},
    tcp::FlowKey,
};

enum PendingTransmit {
    Segments(PendingSegments),
    Reply(Packet),
}
impl PendingTransmit {
    fn flow(&self) -> Option<FlowKey> {
        match self {
            Self::Segments(segments) => Some(segments.flow()),
            Self::Reply(packet) => PendingSegments::new(packet.clone()).map(|part| part.flow()),
        }
    }
}

/// A raw-IP device with one pending ingress and one bounded pending output.
pub(crate) struct RawIpDevice {
    rx: Option<Packet>,
    output: mpsc::Sender<Packet>,
    emitted: u64,
    capabilities: DeviceCapabilities,
    pending_tx: Option<PendingTransmit>,
    path_mtu: Option<PathMtu>,
}

impl RawIpDevice {
    pub(crate) fn new(mtu: usize, output: mpsc::Sender<Packet>) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = mtu;
        capabilities.medium = Medium::Ip;
        Self {
            rx: None,
            output,
            emitted: 0,
            capabilities,
            pending_tx: None,
            path_mtu: None,
        }
    }

    pub(crate) fn push_rx(&mut self, packet: Packet) -> Result<(), Packet> {
        if self.rx.is_some() {
            Err(packet)
        } else {
            self.rx = Some(packet);
            Ok(())
        }
    }

    pub(crate) fn rx_is_empty(&self) -> bool {
        self.rx.is_none()
    }

    pub(crate) fn pending_rx(&self) -> Option<&Packet> {
        self.rx.as_ref()
    }

    pub(crate) fn discard_rx(&mut self) {
        self.rx = None;
    }

    pub(crate) fn emitted(&self) -> u64 {
        self.emitted
    }

    pub(crate) fn tx_is_full(&self) -> bool {
        self.pending_tx.is_some() || self.output.capacity() == 0
    }

    pub(crate) fn enable_path_mtu(&mut self) {
        self.path_mtu = Some(PathMtu::default());
    }

    pub(crate) fn disable_path_mtu(&mut self) {
        self.path_mtu = None;
    }

    pub(crate) fn set_initial_mtu(&mut self, mtu: usize) {
        self.capabilities.max_transmission_unit = mtu;
    }

    pub(crate) fn apply_path_mtu(&mut self, hint: PathMtuHint) -> bool {
        self.path_mtu
            .as_mut()
            .is_some_and(|paths| paths.apply(hint, self.capabilities.max_transmission_unit))
    }

    pub(crate) fn acknowledge(&mut self, packet: &Packet) {
        if let Some(paths) = &mut self.path_mtu {
            paths.acknowledge(packet);
        }
    }

    pub(crate) fn forget_flow(&mut self, incoming: FlowKey) {
        let outgoing = reverse(incoming);
        if let Some(paths) = &mut self.path_mtu {
            paths.forget(outgoing);
        }
        if self
            .pending_tx
            .as_ref()
            .is_some_and(|pending| pending.flow() == Some(outgoing))
        {
            self.pending_tx = None;
        }
    }

    pub(crate) fn clear(&mut self) {
        self.rx = None;
        self.pending_tx = None;
        self.path_mtu = None;
    }

    /// Drain only into the existing raw output queue, without waiting. Every
    /// segment reserves its slot before allocating a packet. A partial drain
    /// retains one original packet and resumes on `PacketStream` notification.
    pub(crate) fn flush_pending(&mut self) {
        while let Some(pending) = &mut self.pending_tx {
            let Ok(permit) = self.output.try_reserve() else {
                break;
            };
            if matches!(pending, PendingTransmit::Reply(_)) {
                let Some(PendingTransmit::Reply(packet)) = self.pending_tx.take() else {
                    unreachable!();
                };
                if let Some(paths) = &mut self.path_mtu {
                    paths.emitted(&packet);
                }
                permit.send(packet);
                self.emitted = self.emitted.wrapping_add(1);
                continue;
            }
            let PendingTransmit::Segments(pending) = pending else {
                unreachable!();
            };
            let budget = self
                .path_mtu
                .as_ref()
                .map_or(self.capabilities.max_transmission_unit, |paths| {
                    paths.budget(pending.flow(), self.capabilities.max_transmission_unit)
                });
            let Some(packet) = pending.next(budget) else {
                self.pending_tx = None;
                break;
            };
            if let Some(paths) = &mut self.path_mtu {
                paths.emitted(&packet);
            }
            permit.send(packet);
            self.emitted = self.emitted.wrapping_add(1);
            if pending.is_finished() {
                self.pending_tx = None;
            }
        }
    }
}

impl Device for RawIpDevice {
    type RxToken<'a> = RawRxToken;
    type TxToken<'a> = RawTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Reserve before consuming ingress: smoltcp can need an immediate
        // response, and concurrent generic UDP senders share this capacity.
        if self.pending_tx.is_some() {
            return None;
        }
        let permit = match self.output.try_reserve() {
            Ok(permit) => Some(permit),
            Err(mpsc::error::TrySendError::Full(()))
                if self.rx.as_ref().is_some_and(is_pure_tcp_ack) =>
            {
                None
            }
            Err(_) => return None,
        };
        let packet = self.rx.take()?;
        Some((
            RawRxToken(packet),
            RawTxToken {
                permit,
                emitted: &mut self.emitted,
                pending: &mut self.pending_tx,
                path_mtu: &mut self.path_mtu,
                mtu: self.capabilities.max_transmission_unit,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.pending_tx.is_some() {
            return None;
        }
        Some(RawTxToken {
            permit: Some(self.output.try_reserve().ok()?),
            emitted: &mut self.emitted,
            pending: &mut self.pending_tx,
            path_mtu: &mut self.path_mtu,
            mtu: self.capabilities.max_transmission_unit,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub(crate) struct RawRxToken(Packet);

impl RxToken for RawRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.0.data())
    }
}

pub(crate) struct RawTxToken<'a> {
    permit: Option<mpsc::Permit<'a, Packet>>,
    emitted: &'a mut u64,
    pending: &'a mut Option<PendingTransmit>,
    path_mtu: &'a mut Option<PathMtu>,
    mtu: usize,
}

impl TxToken for RawTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = vec![0_u8; len];
        let result = f(&mut bytes);
        let mut packet = Packet::new(bytes);
        let Some(permit) = self.permit else {
            // A pure incoming ACK can still require a challenge ACK or RST.
            // Preserve that response in the existing single pending slot;
            // never acknowledge a generated reply by silently dropping it.
            *self.pending = Some(PendingTransmit::Reply(packet));
            return result;
        };
        if let Some(paths) = self.path_mtu.as_mut() {
            // Metadata parsing is limited to trusted smoltcp output. Packets
            // within the path budget keep their allocation and byte contents.
            if let Some(mut pending) = PendingSegments::new(packet.clone()) {
                let budget = paths.budget(pending.flow(), self.mtu);
                if packet.len() > budget {
                    let Some(first) = pending.next(budget) else {
                        return result;
                    };
                    packet = first;
                    if !pending.is_finished() {
                        *self.pending = Some(PendingTransmit::Segments(pending));
                    }
                }
            } else if packet.len() > self.mtu {
                // No UDP boundary splitting or implicit IP fragmentation.
                return result;
            }
            paths.emitted(&packet);
        }
        permit.send(packet);
        *self.emitted = self.emitted.wrapping_add(1);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_tx_consumes_pure_ack_without_allocating_an_output_or_queue() {
        use crate::segmentation::tests::tcp_packet;
        let flow = FlowKey {
            source: "10.23.0.2:4000".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
        };
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1500, output.clone());
        let occupied = Packet::new(vec![0x45; 40]);
        output.try_send(occupied.clone()).unwrap();
        for acknowledgment in 10..13 {
            let ack = tcp_packet(flow, 1, acknowledgment, 16, 0);
            device.push_rx(ack.clone()).unwrap();
            let (rx, tx) = device
                .receive(Instant::now())
                .expect("full TX blocked pure TCP ACK");
            rx.consume(|bytes| assert_eq!(bytes, ack.data()));
            drop(tx); // Valid ordinary ACKs do not require an immediate reply.
            assert!(device.rx_is_empty());
            assert!(device.pending_tx.is_none());
            assert_eq!(device.emitted(), 0);
            assert_eq!(output.capacity(), 0);
        }
        assert_eq!(receiver.try_recv().unwrap(), occupied);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn full_tx_preserves_ack_or_reset_reply_in_the_existing_pending_slot() {
        use crate::segmentation::tests::tcp_packet;
        let flow = FlowKey {
            source: "10.23.0.2:4000".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
        };
        for flags in [16, 20] {
            let (output, mut receiver) = mpsc::channel(1);
            let mut device = RawIpDevice::new(1500, output.clone());
            device.enable_path_mtu();
            let occupied = Packet::new(vec![0x45; 40]);
            output.try_send(occupied.clone()).unwrap();
            device.push_rx(tcp_packet(flow, 1, 10, 16, 0)).unwrap();
            let (rx, tx) = device
                .receive(Instant::now())
                .expect("pure ACK did not enter");
            rx.consume(|_| {});
            let response = tcp_packet(reverse(flow), 10, 1, flags, 0);
            tx.consume(response.len(), |bytes| {
                bytes.copy_from_slice(response.data())
            });
            assert!(device.pending_tx.is_some());
            assert_eq!(device.emitted(), 0);
            assert!(device.transmit(Instant::now()).is_none());
            device.flush_pending();
            assert_eq!(device.emitted(), 0); // Never overwrite or bypass full output.
            assert_eq!(receiver.try_recv().unwrap(), occupied);
            device.flush_pending();
            assert_eq!(receiver.try_recv().unwrap(), response);
            assert_eq!(device.emitted(), 1);
            assert!(device.pending_tx.is_none());
            assert!(receiver.try_recv().is_err());
        }
    }

    #[test]
    fn full_tx_keeps_syn_data_fin_urgent_and_invalid_ack_pending() {
        use crate::segmentation::tests::tcp_packet;
        let flow = FlowKey {
            source: "10.23.0.2:4000".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
        };
        let mut inputs = vec![
            tcp_packet(flow, 1, 0, 2, 0),
            tcp_packet(flow, 1, 10, 16, 1),
            tcp_packet(flow, 1, 10, 17, 0),
            tcp_packet(flow, 1, 10, 20, 0),
            tcp_packet(flow, 1, 10, 48, 0),
        ];
        let mut invalid = tcp_packet(flow, 1, 10, 16, 0).data().to_vec();
        *invalid.last_mut().unwrap() ^= 1;
        inputs.push(Packet::new(invalid));
        for input in inputs {
            let (output, _receiver) = mpsc::channel(1);
            let mut device = RawIpDevice::new(1500, output.clone());
            output.try_send(Packet::new(vec![0x45; 40])).unwrap();
            device.push_rx(input).unwrap();
            assert!(device.receive(Instant::now()).is_none());
            assert!(!device.rx_is_empty());
            assert!(device.pending_tx.is_none());
        }
    }

    #[test]
    fn full_tx_pending_reply_blocks_a_second_ack_and_clear_releases_both() {
        use crate::segmentation::tests::tcp_packet;
        let flow = FlowKey {
            source: "10.23.0.2:4000".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
        };
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1500, output.clone());
        output.try_send(Packet::new(vec![0x45; 40])).unwrap();
        device.push_rx(tcp_packet(flow, 1, 10, 16, 0)).unwrap();
        let (rx, tx) = device
            .receive(Instant::now())
            .expect("pure ACK did not enter");
        rx.consume(|_| {});
        let response = tcp_packet(reverse(flow), 10, 1, 16, 0);
        tx.consume(response.len(), |bytes| {
            bytes.copy_from_slice(response.data())
        });
        device.push_rx(tcp_packet(flow, 1, 11, 16, 0)).unwrap();
        assert!(device.receive(Instant::now()).is_none());
        assert!(device.transmit(Instant::now()).is_none());
        assert!(device.pending_tx.is_some() && !device.rx_is_empty());
        device.clear();
        assert!(device.pending_tx.is_none() && device.rx_is_empty());
        receiver.try_recv().unwrap();
        device.flush_pending();
        assert!(receiver.try_recv().is_err());
        assert_eq!(device.emitted(), 0);
    }

    #[test]
    fn full_tx_queue_does_not_consume_rx() {
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output.clone());
        device.push_rx(Packet::new(vec![0x45; 40])).unwrap();
        output.try_send(Packet::new(vec![0x45; 40])).unwrap();

        assert!(device.receive(Instant::now()).is_none());
        assert!(!device.rx_is_empty());
        assert!(device.tx_is_full());
        receiver.try_recv().unwrap();
        let (rx, tx) = device.receive(Instant::now()).unwrap();
        rx.consume(|bytes| assert_eq!(bytes, &[0x45; 40]));
        drop(tx);
        assert!(device.rx_is_empty());
        assert!(!device.tx_is_full());
    }

    #[test]
    fn unused_tx_permit_returns_capacity_without_a_packet() {
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output.clone());
        let token = device.transmit(Instant::now()).unwrap();
        assert_eq!(output.capacity(), 0);
        drop(token);
        assert_eq!(output.capacity(), 1);
        assert_eq!(device.emitted(), 0);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn consumed_tx_permit_sends_directly_to_the_only_output_queue() {
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output);
        device
            .transmit(Instant::now())
            .unwrap()
            .consume(4, |bytes| bytes.copy_from_slice(&[0x45, 1, 2, 3]));
        assert_eq!(device.emitted(), 1);
        assert!(device.tx_is_full());
        assert_eq!(receiver.try_recv().unwrap().data(), &[0x45, 1, 2, 3]);
        assert!(!device.tx_is_full());
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn one_pending_ingress_is_not_overwritten() {
        let (output, _receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output);
        device.push_rx(Packet::new(vec![0x45, 1])).unwrap();
        let rejected = device.push_rx(Packet::new(vec![0x45, 2])).unwrap_err();
        assert_eq!(rejected.data(), &[0x45, 2]);
        let (rx, tx) = device.receive(Instant::now()).unwrap();
        rx.consume(|bytes| assert_eq!(bytes, &[0x45, 1]));
        drop(tx);
    }

    #[test]
    fn closed_output_never_consumes_pending_ingress() {
        let (output, receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1_500, output);
        device.push_rx(Packet::new(vec![0x45; 40])).unwrap();
        drop(receiver);
        assert!(device.receive(Instant::now()).is_none());
        assert!(device.transmit(Instant::now()).is_none());
        assert!(!device.rx_is_empty());
    }

    #[test]
    fn split_output_resumes_with_one_reserved_slot_and_adopts_a_smaller_budget() {
        use crate::segmentation::tests::{hint, tcp_packet};
        let flow = FlowKey {
            source: "10.23.0.2:4000".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
        };
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(9000, output);
        device.enable_path_mtu();
        let first = tcp_packet(flow, 1000, 91, 16, 7000);
        device
            .transmit(Instant::now())
            .unwrap()
            .consume(first.len(), |bytes| bytes.copy_from_slice(first.data()));
        let emitted = receiver.try_recv().unwrap();
        assert!(device.apply_path_mtu(hint(&emitted, 1280)));

        let next = tcp_packet(flow, 10000, 91, 16, 7000);
        device
            .transmit(Instant::now())
            .unwrap()
            .consume(next.len(), |bytes| bytes.copy_from_slice(next.data()));
        assert_eq!(device.emitted(), 2);
        assert!(device.pending_tx.is_some() && device.transmit(Instant::now()).is_none());
        device.flush_pending();
        assert_eq!(device.emitted(), 2); // full queue, no segment allocation
        let segment = receiver.try_recv().unwrap();
        assert_eq!(segment.len(), 1280);
        let mut unsent = hint(&segment, 576);
        unsent.sequence = 12000; // original exists, this tail has not left it
        assert!(!device.apply_path_mtu(unsent));
        assert!(device.apply_path_mtu(hint(&segment, 576)));
        let mut payload_size = segment.len() - 56;
        while device.pending_tx.is_some() {
            device.flush_pending();
            let packet = receiver.try_recv().unwrap();
            assert!(packet.len() <= 576);
            payload_size += packet.len() - 56;
        }
        assert_eq!(payload_size, 7000);
        assert!(device.transmit(Instant::now()).is_some());
        // New oversized output can be discarded synchronously without having
        // to drain the consumer, including its retained original allocation.
        device
            .transmit(Instant::now())
            .unwrap()
            .consume(next.len(), |bytes| bytes.copy_from_slice(next.data()));
        assert!(device.pending_tx.is_some());
        device.clear();
        assert!(device.pending_tx.is_none() && device.path_mtu.is_none());
    }

    #[test]
    fn reclaimed_tuple_discards_pending_bytes_and_old_quote_authorization() {
        use crate::segmentation::tests::{hint, tcp_packet};
        let flow = FlowKey {
            source: "10.23.0.2:4000".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
        };
        let (output, mut receiver) = mpsc::channel(1);
        let mut device = RawIpDevice::new(1500, output);
        device.enable_path_mtu();
        let packet = tcp_packet(flow, 1000, 91, 16, 1400);
        device
            .transmit(Instant::now())
            .unwrap()
            .consume(packet.len(), |bytes| bytes.copy_from_slice(packet.data()));
        let emitted = receiver.try_recv().unwrap();
        assert!(device.apply_path_mtu(hint(&emitted, 576)));
        device
            .transmit(Instant::now())
            .unwrap()
            .consume(packet.len(), |bytes| bytes.copy_from_slice(packet.data()));
        assert!(device.pending_tx.is_some());
        device.forget_flow(reverse(flow));
        assert!(device.pending_tx.is_none());
        assert!(!device.apply_path_mtu(hint(&emitted, 296)));
        receiver.try_recv().unwrap();
        device
            .transmit(Instant::now())
            .unwrap()
            .consume(packet.len(), |bytes| bytes.copy_from_slice(packet.data()));
        assert_eq!(receiver.try_recv().unwrap().len(), packet.len());
    }
}
