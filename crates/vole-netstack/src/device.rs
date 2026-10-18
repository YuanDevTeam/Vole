use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

use crate::{
    Packet,
    pmtu::PathMtuHint,
    segmentation::{PathMtu, PendingSegments, reverse},
    tcp::FlowKey,
};

/// A raw-IP device with one pending ingress and reserved bounded output slots.
pub(crate) struct RawIpDevice {
    rx: Option<Packet>,
    output: mpsc::Sender<Packet>,
    emitted: u64,
    capabilities: DeviceCapabilities,
    pending_tx: Option<PendingSegments>,
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
            .is_some_and(|pending| pending.flow() == outgoing)
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
        let permit = self.output.try_reserve().ok()?;
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
            permit: self.output.try_reserve().ok()?,
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
    permit: mpsc::Permit<'a, Packet>,
    emitted: &'a mut u64,
    pending: &'a mut Option<PendingSegments>,
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
                        *self.pending = Some(pending);
                    }
                }
            } else if packet.len() > self.mtu {
                // No UDP boundary splitting or implicit IP fragmentation.
                return result;
            }
            paths.emitted(&packet);
        }
        self.permit.send(packet);
        *self.emitted = self.emitted.wrapping_add(1);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
