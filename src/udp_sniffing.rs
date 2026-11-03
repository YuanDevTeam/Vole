//! Shared bounded QUIC v1/v2 first-flight sniffing for UDP ingress adapters.
use crate::{
    quic_sniffer::{
        QuicConnectionKey, QuicSniffOutcome, QuicSniffer, quic_connection_key,
        quic_has_unsupported_version,
    },
    session::{Datagram, Destination},
};
use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant as TokioInstant;

pub(crate) const QUIC_SNIFF_FLOW_MAX: usize = 4;
pub(crate) const QUIC_SNIFF_PENDING_DATAGRAM_MAX: usize = 8;
pub(crate) const QUIC_SNIFF_PENDING_BYTES_MAX: usize = 32 * 1024;
pub(crate) const QUIC_SNIFF_READY_DATAGRAM_MAX: usize = QUIC_SNIFF_PENDING_DATAGRAM_MAX + 1;
pub(crate) const QUIC_SNIFF_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) trait SniffPacket {
    type Key: Clone + Eq + Hash;
    fn destination_key(&self) -> Self::Key;
    fn payload(&self) -> &[u8];
}
impl SniffPacket for Datagram {
    type Key = Destination;
    fn destination_key(&self) -> Destination {
        self.remote.clone()
    }
    fn payload(&self) -> &[u8] {
        &self.payload
    }
}
#[cfg(feature = "tun")]
impl SniffPacket for vole_netstack::UdpDatagram {
    type Key = std::net::SocketAddr;
    fn destination_key(&self) -> std::net::SocketAddr {
        self.destination
    }
    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub(crate) trait QuicSniffEngine {
    fn ingest(&mut self, packet: &[u8]) -> QuicSniffOutcome;

    fn authenticated_initial_in_last_ingest(&self) -> bool;
}

impl QuicSniffEngine for QuicSniffer {
    fn ingest(&mut self, packet: &[u8]) -> QuicSniffOutcome {
        QuicSniffer::ingest(self, packet)
    }

    fn authenticated_initial_in_last_ingest(&self) -> bool {
        QuicSniffer::authenticated_initial_in_last_ingest(self)
    }
}

pub(crate) struct PreparedDatagram<P> {
    pub(crate) datagram: P,
    pub(crate) sniffed_domain: Option<Arc<str>>,
    /// Carried once, on the first released datagram of an authenticated Initial flight.
    pub(crate) flow_id: Option<QuicConnectionKey>,
}

impl<P> PreparedDatagram<P> {
    pub(crate) fn without_domain(datagram: P) -> Self {
        Self {
            datagram,
            sniffed_domain: None,
            flow_id: None,
        }
    }

    pub(crate) fn with_domain(datagram: P, domain: Arc<str>) -> Self {
        Self {
            datagram,
            sniffed_domain: Some(domain),
            flow_id: None,
        }
    }

    pub(crate) fn with_flow_id(mut self, flow_id: Option<QuicConnectionKey>) -> Self {
        self.flow_id = flow_id;
        self
    }
}

pub(crate) struct PendingQuicFlow<S, P> {
    sniffer: S,
    connection_key: Option<QuicConnectionKey>,
    datagrams: VecDeque<PreparedDatagram<P>>,
    buffered_bytes: usize,
    deadline: TokioInstant,
}

pub(crate) struct CompletedQuicFlow {
    connection_key: Option<QuicConnectionKey>,
    last_used: TokioInstant,
}

pub(crate) enum QuicFlowState<S, P> {
    Pending(PendingQuicFlow<S, P>),
    Matched {
        domain: Arc<str>,
        completed: CompletedQuicFlow,
    },
    NoDomain(CompletedQuicFlow),
}

pub(crate) enum IngressResult<P> {
    Buffered,
    Forward(PreparedDatagram<P>),
    Replay(VecDeque<PreparedDatagram<P>>),
}

fn starts_new_quic_connection(
    current: &Option<QuicConnectionKey>,
    observed: &Option<QuicConnectionKey>,
) -> bool {
    observed
        .as_ref()
        .is_some_and(|observed| current.as_ref() != Some(observed))
}

fn prepend_quic_replay<P>(
    mut replay: VecDeque<PreparedDatagram<P>>,
    next: IngressResult<P>,
) -> IngressResult<P> {
    if replay.is_empty() {
        return next;
    }
    match next {
        IngressResult::Buffered => IngressResult::Replay(replay),
        IngressResult::Forward(prepared) => {
            replay.push_back(prepared);
            IngressResult::Replay(replay)
        }
        IngressResult::Replay(mut next) => {
            replay.append(&mut next);
            IngressResult::Replay(replay)
        }
    }
}

pub(crate) struct SniffState<S, F, P: SniffPacket> {
    pub(crate) flows: HashMap<P::Key, QuicFlowState<S, P>>,
    pub(crate) pending_datagrams: usize,
    pub(crate) pending_bytes: usize,
    new_sniffer: F,
    idle_timeout: Duration,
}

impl<S, F, P> SniffState<S, F, P>
where
    P: SniffPacket,
    S: QuicSniffEngine,
    F: FnMut() -> S,
{
    pub(crate) fn with_idle_timeout(new_sniffer: F, idle_timeout: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            pending_datagrams: 0,
            pending_bytes: 0,
            new_sniffer,
            idle_timeout,
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<TokioInstant> {
        self.flows
            .values()
            .filter_map(|state| match state {
                QuicFlowState::Pending(pending) => Some(pending.deadline),
                QuicFlowState::Matched { .. } | QuicFlowState::NoDomain(_) => None,
            })
            .min()
    }

    pub(crate) fn ingest_datagram(&mut self, datagram: P, now: TokioInstant) -> IngressResult<P> {
        let destination = datagram.destination_key();
        let connection_key = quic_connection_key(datagram.payload());
        let state = self.flows.remove(&destination).filter(|state| match state {
            QuicFlowState::Matched { completed, .. } | QuicFlowState::NoDomain(completed) => {
                now.saturating_duration_since(completed.last_used) < self.idle_timeout
            }
            QuicFlowState::Pending(_) => true,
        });
        if connection_key.is_none() && quic_has_unsupported_version(datagram.payload()) {
            return self.fail_open_unsupported_version(datagram, state, now);
        }
        let Some(state) = state else {
            return self.start_flow(datagram, connection_key, now);
        };
        match state {
            QuicFlowState::Matched {
                domain,
                mut completed,
            } => {
                if starts_new_quic_connection(&completed.connection_key, &connection_key) {
                    let mut candidate = (self.new_sniffer)();
                    let outcome = candidate.ingest(datagram.payload());
                    if candidate.authenticated_initial_in_last_ingest() {
                        return self.commit_started_flow(
                            datagram,
                            connection_key,
                            now,
                            candidate,
                            outcome,
                        );
                    }
                }
                completed.last_used = now;
                self.flows.insert(
                    destination,
                    QuicFlowState::Matched {
                        domain: domain.clone(),
                        completed,
                    },
                );
                IngressResult::Forward(PreparedDatagram::with_domain(datagram, domain))
            }
            QuicFlowState::NoDomain(mut completed) => {
                if starts_new_quic_connection(&completed.connection_key, &connection_key) {
                    let mut candidate = (self.new_sniffer)();
                    let outcome = candidate.ingest(datagram.payload());
                    if candidate.authenticated_initial_in_last_ingest() {
                        return self.commit_started_flow(
                            datagram,
                            connection_key,
                            now,
                            candidate,
                            outcome,
                        );
                    }
                }
                completed.last_used = now;
                self.flows
                    .insert(destination, QuicFlowState::NoDomain(completed));
                IngressResult::Forward(PreparedDatagram::without_domain(datagram))
            }
            QuicFlowState::Pending(mut pending) => {
                if starts_new_quic_connection(&pending.connection_key, &connection_key) {
                    let outcome = pending.sniffer.ingest(datagram.payload());
                    if pending.sniffer.authenticated_initial_in_last_ingest() {
                        // A non-Initial prefix can have entered the pending
                        // state before any Initial keys existed. Adopt only
                        // its first authenticated identity; a later header
                        // DCID accepted by existing keys is the same flow.
                        if pending.connection_key.is_none() {
                            pending.connection_key = connection_key;
                            if let Some(first) = pending.datagrams.front_mut() {
                                first.flow_id = pending.connection_key.clone();
                            }
                        }
                        return self.apply_pending_outcome(
                            destination,
                            pending,
                            datagram,
                            outcome,
                            now,
                        );
                    }
                    let mut candidate = (self.new_sniffer)();
                    let outcome = candidate.ingest(datagram.payload());
                    if !candidate.authenticated_initial_in_last_ingest() {
                        self.flows
                            .insert(destination, QuicFlowState::Pending(pending));
                        return IngressResult::Forward(PreparedDatagram::without_domain(datagram));
                    }
                    self.release_pending(&pending);
                    let replay = pending.datagrams;
                    let next =
                        self.commit_started_flow(datagram, connection_key, now, candidate, outcome);
                    return prepend_quic_replay(replay, next);
                }
                let outcome = pending.sniffer.ingest(datagram.payload());
                self.apply_pending_outcome(destination, pending, datagram, outcome, now)
            }
        }
    }

    fn fail_open_unsupported_version(
        &mut self,
        datagram: P,
        state: Option<QuicFlowState<S, P>>,
        now: TokioInstant,
    ) -> IngressResult<P> {
        let destination = datagram.destination_key();
        match state {
            Some(QuicFlowState::Pending(mut pending)) => {
                self.release_pending(&pending);
                pending
                    .datagrams
                    .push_back(PreparedDatagram::without_domain(datagram));
                self.flows.insert(
                    destination,
                    QuicFlowState::NoDomain(CompletedQuicFlow {
                        connection_key: None,
                        last_used: now,
                    }),
                );
                IngressResult::Replay(pending.datagrams)
            }
            Some(QuicFlowState::Matched { .. }) | Some(QuicFlowState::NoDomain(_)) => {
                self.flows.insert(
                    destination,
                    QuicFlowState::NoDomain(CompletedQuicFlow {
                        connection_key: None,
                        last_used: now,
                    }),
                );
                IngressResult::Forward(PreparedDatagram::without_domain(datagram))
            }
            None => {
                if self.make_room_for_flow() {
                    self.flows.insert(
                        destination,
                        QuicFlowState::NoDomain(CompletedQuicFlow {
                            connection_key: None,
                            last_used: now,
                        }),
                    );
                }
                IngressResult::Forward(PreparedDatagram::without_domain(datagram))
            }
        }
    }

    fn start_flow(
        &mut self,
        datagram: P,
        connection_key: Option<QuicConnectionKey>,
        now: TokioInstant,
    ) -> IngressResult<P> {
        if !self.make_room_for_flow() {
            return IngressResult::Forward(PreparedDatagram::without_domain(datagram));
        }
        let mut sniffer = (self.new_sniffer)();
        let outcome = sniffer.ingest(datagram.payload());
        self.commit_started_flow(datagram, connection_key, now, sniffer, outcome)
    }

    fn commit_started_flow(
        &mut self,
        datagram: P,
        connection_key: Option<QuicConnectionKey>,
        now: TokioInstant,
        sniffer: S,
        outcome: QuicSniffOutcome,
    ) -> IngressResult<P> {
        let destination = datagram.destination_key();
        // A parseable header alone must not suppress a later authenticated
        // Initial with the same DCID, or claim a connection identity.
        let connection_key = sniffer
            .authenticated_initial_in_last_ingest()
            .then_some(connection_key)
            .flatten();
        let flow_id = connection_key.clone();
        match outcome {
            QuicSniffOutcome::NeedMoreData if self.can_buffer(datagram.payload().len()) => {
                let buffered_bytes = datagram.payload().len();
                let mut datagrams = VecDeque::new();
                datagrams
                    .push_back(PreparedDatagram::without_domain(datagram).with_flow_id(flow_id));
                self.pending_datagrams += 1;
                self.pending_bytes += buffered_bytes;
                self.flows.insert(
                    destination,
                    QuicFlowState::Pending(PendingQuicFlow {
                        sniffer,
                        connection_key,
                        datagrams,
                        buffered_bytes,
                        deadline: now + QUIC_SNIFF_TIMEOUT,
                    }),
                );
                IngressResult::Buffered
            }
            QuicSniffOutcome::Matched(domain) => {
                let domain: Arc<str> = Arc::from(domain);
                self.flows.insert(
                    destination,
                    QuicFlowState::Matched {
                        domain: domain.clone(),
                        completed: CompletedQuicFlow {
                            connection_key,
                            last_used: now,
                        },
                    },
                );
                IngressResult::Forward(
                    PreparedDatagram::with_domain(datagram, domain).with_flow_id(flow_id),
                )
            }
            QuicSniffOutcome::NeedMoreData
            | QuicSniffOutcome::EchExtensionPresent
            | QuicSniffOutcome::NotMatched
            | QuicSniffOutcome::LimitReached => {
                self.flows.insert(
                    destination,
                    QuicFlowState::NoDomain(CompletedQuicFlow {
                        connection_key,
                        last_used: now,
                    }),
                );
                IngressResult::Forward(
                    PreparedDatagram::without_domain(datagram).with_flow_id(flow_id),
                )
            }
        }
    }

    fn apply_pending_outcome(
        &mut self,
        destination: P::Key,
        mut pending: PendingQuicFlow<S, P>,
        datagram: P,
        outcome: QuicSniffOutcome,
        now: TokioInstant,
    ) -> IngressResult<P> {
        match outcome {
            QuicSniffOutcome::NeedMoreData if self.can_buffer(datagram.payload().len()) => {
                let payload_len = datagram.payload().len();
                pending.buffered_bytes += payload_len;
                pending
                    .datagrams
                    .push_back(PreparedDatagram::without_domain(datagram));
                self.pending_datagrams += 1;
                self.pending_bytes += payload_len;
                self.flows
                    .insert(destination, QuicFlowState::Pending(pending));
                IngressResult::Buffered
            }
            QuicSniffOutcome::Matched(domain) => {
                self.finish_pending(destination, pending, datagram, Some(Arc::from(domain)), now)
            }
            QuicSniffOutcome::NeedMoreData
            | QuicSniffOutcome::EchExtensionPresent
            | QuicSniffOutcome::NotMatched
            | QuicSniffOutcome::LimitReached => {
                self.finish_pending(destination, pending, datagram, None, now)
            }
        }
    }

    fn make_room_for_flow(&mut self) -> bool {
        if self.flows.len() < QUIC_SNIFF_FLOW_MAX {
            return true;
        }
        let oldest_completed = self
            .flows
            .iter()
            .filter_map(|(destination, state)| match state {
                QuicFlowState::Matched { completed, .. } | QuicFlowState::NoDomain(completed) => {
                    Some((destination.clone(), completed.last_used))
                }
                QuicFlowState::Pending(_) => None,
            })
            .min_by_key(|(_, last_used)| *last_used)
            .map(|(destination, _)| destination);
        if let Some(destination) = oldest_completed {
            self.flows.remove(&destination);
            true
        } else {
            false
        }
    }

    fn can_buffer(&self, bytes: usize) -> bool {
        self.pending_datagrams < QUIC_SNIFF_PENDING_DATAGRAM_MAX
            && self
                .pending_bytes
                .checked_add(bytes)
                .is_some_and(|total| total <= QUIC_SNIFF_PENDING_BYTES_MAX)
    }

    fn finish_pending(
        &mut self,
        destination: P::Key,
        mut pending: PendingQuicFlow<S, P>,
        datagram: P,
        domain: Option<Arc<str>>,
        now: TokioInstant,
    ) -> IngressResult<P> {
        self.release_pending(&pending);
        pending
            .datagrams
            .push_back(PreparedDatagram::without_domain(datagram));
        if let Some(domain) = &domain {
            for buffered in &mut pending.datagrams {
                buffered.sniffed_domain = Some(domain.clone());
            }
        }
        let completed = CompletedQuicFlow {
            connection_key: pending.connection_key,
            last_used: now,
        };
        self.flows.insert(
            destination,
            match domain {
                Some(domain) => QuicFlowState::Matched { domain, completed },
                None => QuicFlowState::NoDomain(completed),
            },
        );
        IngressResult::Replay(pending.datagrams)
    }

    pub(crate) fn expire(&mut self, now: TokioInstant) -> VecDeque<PreparedDatagram<P>> {
        let destinations = self
            .flows
            .iter()
            .filter_map(|(destination, state)| match state {
                QuicFlowState::Pending(pending) if pending.deadline <= now => {
                    Some(destination.clone())
                }
                QuicFlowState::Pending(_)
                | QuicFlowState::Matched { .. }
                | QuicFlowState::NoDomain(_) => None,
            })
            .collect::<Vec<_>>();
        let mut replay = VecDeque::new();
        for destination in destinations {
            let Some(QuicFlowState::Pending(mut pending)) = self.flows.remove(&destination) else {
                continue;
            };
            self.release_pending(&pending);
            replay.append(&mut pending.datagrams);
            self.flows.insert(
                destination,
                QuicFlowState::NoDomain(CompletedQuicFlow {
                    connection_key: pending.connection_key,
                    last_used: now,
                }),
            );
        }
        replay
    }

    fn release_pending(&mut self, pending: &PendingQuicFlow<S, P>) {
        self.pending_datagrams = self
            .pending_datagrams
            .saturating_sub(pending.datagrams.len());
        self.pending_bytes = self.pending_bytes.saturating_sub(pending.buffered_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    struct Script(VecDeque<QuicSniffOutcome>);
    impl QuicSniffEngine for Script {
        fn ingest(&mut self, _: &[u8]) -> QuicSniffOutcome {
            self.0.pop_front().expect("scripted result")
        }
        fn authenticated_initial_in_last_ingest(&self) -> bool {
            false
        }
    }
    fn packet(host: &str, bytes: &'static [u8]) -> Datagram {
        Datagram {
            remote: Destination::domain(host, 443).unwrap(),
            payload: Bytes::from_static(bytes),
            sniffed_domain: None,
        }
    }

    #[test]
    fn socks_domain_keys_share_quic_reassembly_and_exact_fail_open_replay() {
        let mut state = SniffState::with_idle_timeout(
            || {
                Script(VecDeque::from([
                    QuicSniffOutcome::NeedMoreData,
                    QuicSniffOutcome::Matched("sniff.example".into()),
                ]))
            },
            Duration::from_secs(30),
        );
        let now = TokioInstant::now();
        assert!(matches!(
            state.ingest_datagram(packet("first.example", b"first fragment"), now),
            IngressResult::Buffered
        ));
        assert!(matches!(
            state.ingest_datagram(packet("second.example", b"isolated"), now),
            IngressResult::Buffered
        ));
        let IngressResult::Replay(replay) =
            state.ingest_datagram(packet("first.example", b"second fragment"), now)
        else {
            panic!("completed domain key releases its own flight")
        };
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0].datagram.payload, b"first fragment".as_slice());
        assert_eq!(replay[1].datagram.payload, b"second fragment".as_slice());
        assert!(
            replay
                .iter()
                .all(|item| item.sniffed_domain.as_deref() == Some("sniff.example"))
        );
        assert_eq!(state.pending_datagrams, 1);
        let replay = state.expire(now + QUIC_SNIFF_TIMEOUT);
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].datagram.payload, b"isolated".as_slice());
        assert!(replay[0].sniffed_domain.is_none());
        assert_eq!(state.pending_bytes, 0);
    }

    #[test]
    fn socks_ech_and_shared_packet_budget_preserve_original_datagrams() {
        let mut state = SniffState::with_idle_timeout(
            || {
                Script(VecDeque::from([
                    QuicSniffOutcome::NeedMoreData,
                    QuicSniffOutcome::EchExtensionPresent,
                ]))
            },
            Duration::from_secs(30),
        );
        let now = TokioInstant::now();
        assert!(matches!(
            state.ingest_datagram(packet("ech.example", b"prefix"), now),
            IngressResult::Buffered
        ));
        let IngressResult::Replay(replay) =
            state.ingest_datagram(packet("ech.example", b"outer name"), now)
        else {
            panic!("ECH must release bytes without an outer hint")
        };
        assert!(replay.iter().all(|item| item.sniffed_domain.is_none()));
        assert_eq!(replay[0].datagram.payload, b"prefix".as_slice());
        assert_eq!(replay[1].datagram.payload, b"outer name".as_slice());
        let mut state = SniffState::with_idle_timeout(
            || {
                Script(VecDeque::from(vec![
                    QuicSniffOutcome::NeedMoreData;
                    QUIC_SNIFF_PENDING_DATAGRAM_MAX + 1
                ]))
            },
            Duration::from_secs(30),
        );
        for _ in 0..QUIC_SNIFF_PENDING_DATAGRAM_MAX {
            assert!(matches!(
                state.ingest_datagram(packet("full.example", b"payload"), now),
                IngressResult::Buffered
            ));
        }
        let IngressResult::Replay(replay) =
            state.ingest_datagram(packet("full.example", b"overflow"), now)
        else {
            panic!("full shared budget must release the pending flight")
        };
        assert_eq!(replay.len(), QUIC_SNIFF_READY_DATAGRAM_MAX);
        assert_eq!(
            replay.back().unwrap().datagram.payload,
            b"overflow".as_slice()
        );
        assert_eq!(state.pending_datagrams, 0);
        assert_eq!(state.pending_bytes, 0);
    }
}
