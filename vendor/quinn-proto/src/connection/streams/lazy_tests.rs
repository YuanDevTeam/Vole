//! Vole regressions for sparse, protocol-sized remote stream permission.
use super::*;
use crate::{
    ReadableError, RecvStream, SendStream, TransportErrorCode,
    connection::{State as ConnState, Streams},
};
use bytes::Bytes;

fn make(credit: u64) -> StreamsState {
    StreamsState::new(
        Side::Client,
        VarInt::from_u64(credit).unwrap(),
        VarInt::from_u64(credit).unwrap(),
        4096,
        4096u32.into(),
        1024u32.into(),
    )
}

fn receive(state: &mut StreamsState, id: StreamId, fin: bool) {
    assert_eq!(
        state.received(
            frame::Stream {
                id,
                offset: 0,
                fin,
                data: Bytes::new(),
            },
            0,
        ),
        Ok(ShouldTransmit(false)),
    );
}

#[test]
fn vole_lazy_huge_permission_uses_constant_initial_metadata() {
    let mut state = make(MAX_STREAM_COUNT);
    assert_eq!(state.send.capacity(), 0);
    assert_eq!(state.recv.capacity(), 0);
    assert_eq!(state.unmaterialized_remote[0].len(), 1);
    assert_eq!(state.unmaterialized_remote[1].len(), 1);
    for dir in Dir::iter() {
        assert!(state.unmaterialized_remote[dir as usize].contains(MAX_STREAM_COUNT - 1));
        assert_eq!(state.max_remote[dir as usize], MAX_STREAM_COUNT);
    }
    state.set_params(&TransportParameters {
        initial_max_streams_bidi: 3u32.into(),
        initial_max_stream_data_bidi_local: 7u32.into(),
        ..TransportParameters::default()
    });
    assert!(state.send.is_empty());
    assert!(state.recv.is_empty());
    assert_eq!(state.max[Dir::Bi as usize], 3);
}

#[test]
fn vole_lazy_high_id_accepts_implicit_gaps_one_at_a_time() {
    let mut state = make(MAX_STREAM_COUNT);
    let high = 1 << 40;
    let id = StreamId::new(Side::Server, Dir::Bi, high);
    receive(&mut state, id, false);
    assert_eq!(state.recv.len(), 1);
    assert_eq!(state.send.len(), 1);
    assert_eq!(state.next_remote[Dir::Bi as usize], high + 1);
    assert_eq!(state.poll(), Some(StreamEvent::Opened { dir: Dir::Bi }));
    let connection = ConnState::Established;
    {
        let mut streams = Streams {
            state: &mut state,
            conn_state: &connection,
        };
        assert_eq!(streams.remote_open_streams(Dir::Bi), high + 1);
        assert_eq!(
            streams.accept(Dir::Bi),
            Some(StreamId::new(Side::Server, Dir::Bi, 0))
        );
        assert_eq!(
            streams.accept(Dir::Bi),
            Some(StreamId::new(Side::Server, Dir::Bi, 1))
        );
        assert_eq!(streams.accept(Dir::Uni), None);
        assert_eq!(streams.send_streams(), 2);
    }
    assert_eq!(state.recv.len(), 3);
    assert_eq!(state.send.len(), 3);
    let first = StreamId::new(Side::Server, Dir::Bi, 0);
    let mut pending = Retransmits::default();
    let mut receiver = RecvStream {
        id: first,
        state: &mut state,
        pending: &mut pending,
    };
    assert_eq!(
        receiver.read(true).unwrap().next(1),
        Err(crate::ReadError::Blocked)
    );
    assert_eq!(state.next_reported_remote[Dir::Bi as usize], 2);
}

#[test]
fn vole_lazy_first_frame_kinds_materialize_only_the_target() {
    for kind in 0..4 {
        let mut state = make(128);
        let id = StreamId::new(Side::Server, Dir::Bi, 99);
        match kind {
            0 => receive(&mut state, id, false),
            1 => {
                let _ = state
                    .received_reset(frame::ResetStream {
                        id,
                        error_code: 4u32.into(),
                        final_offset: 0u32.into(),
                    })
                    .unwrap();
            }
            2 => state.received_stop_sending(id, 4u32.into()),
            3 => state.received_max_stream_data(id, 9).unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(state.send.len(), 1);
        assert_eq!(state.recv.len(), 1);
        assert!(!state.unmaterialized_remote[Dir::Bi as usize].contains(99));
        assert!(state.unmaterialized_remote[Dir::Bi as usize].contains(98));
        assert_eq!(state.next_remote[Dir::Bi as usize], 100);
        assert_eq!(state.poll(), Some(StreamEvent::Opened { dir: Dir::Bi }));
    }
    let mut state = make(128);
    let uni = StreamId::new(Side::Server, Dir::Uni, 99);
    let _ = state
        .received_reset(frame::ResetStream {
            id: uni,
            error_code: 4u32.into(),
            final_offset: 0u32.into(),
        })
        .unwrap();
    assert_eq!(state.recv.len(), 1);
    assert_eq!(state.send.len(), 0);
}

#[test]
fn vole_lazy_invalid_frame_ids_do_not_consume_permission() {
    let mut state = make(2);
    let id = StreamId::new(Side::Server, Dir::Bi, 2);
    assert_eq!(
        state
            .received(
                frame::Stream {
                    id,
                    offset: 0,
                    fin: false,
                    data: Bytes::new()
                },
                0
            )
            .unwrap_err()
            .code,
        TransportErrorCode::STREAM_LIMIT_ERROR
    );
    assert_eq!(
        state
            .received_reset(frame::ResetStream {
                id,
                error_code: 0u32.into(),
                final_offset: 0u32.into()
            })
            .unwrap_err()
            .code,
        TransportErrorCode::STREAM_LIMIT_ERROR
    );
    assert_eq!(
        state.received_max_stream_data(id, 1).unwrap_err().code,
        TransportErrorCode::STREAM_LIMIT_ERROR
    );
    // Preserve the existing STOP_SENDING dispatch contract: a remote bidi ID
    // without a permitted slot is ignored, whereas the outer dispatcher rejects
    // recv-only and locally unopened IDs before this consumer is reached.
    state.received_stop_sending(id, 0u32.into());
    let uni = StreamId::new(Side::Server, Dir::Uni, 0);
    assert_eq!(
        state.received_max_stream_data(uni, 1).unwrap_err().code,
        TransportErrorCode::STREAM_STATE_ERROR
    );
    assert!(state.send.is_empty());
    assert!(state.recv.is_empty());
    assert_eq!(state.unmaterialized_remote[0].len(), 1);
    assert!(state.unmaterialized_remote[0].contains(0));
    assert!(state.unmaterialized_remote[0].contains(1));
}

#[test]
fn vole_lazy_closed_bidi_halves_are_not_revived_by_late_frames() {
    let mut state = make(4);
    let id = StreamId::new(Side::Server, Dir::Bi, 0);
    let _ = state
        .received_reset(frame::ResetStream {
            id,
            error_code: 3u32.into(),
            final_offset: 0u32.into(),
        })
        .unwrap();
    let connection = ConnState::Established;
    assert_eq!(
        (Streams {
            state: &mut state,
            conn_state: &connection
        })
        .accept(Dir::Bi),
        Some(id)
    );
    let mut pending = Retransmits::default();
    {
        let mut receiver = RecvStream {
            id,
            state: &mut state,
            pending: &mut pending,
        };
        assert_eq!(receiver.received_reset(), Ok(Some(3u32.into())));
        assert_eq!(receiver.read(true).err(), Some(ReadableError::ClosedStream));
    }
    assert!(!state.recv.contains_key(&id));
    assert!(state.send.contains_key(&id));
    receive(&mut state, id, true);
    let _ = state
        .received_reset(frame::ResetStream {
            id,
            error_code: 5u32.into(),
            final_offset: 0u32.into(),
        })
        .unwrap();
    assert!(!state.recv.contains_key(&id));
    state.received_max_stream_data(id, 17).unwrap();
    assert_eq!(state.send[&id].as_ref().unwrap().max_data, 17);
    {
        let mut sender = SendStream {
            id,
            state: &mut state,
            pending: &mut pending,
            conn_state: &connection,
        };
        sender.reset(0u32.into()).unwrap();
    }
    state.reset_acked(id);
    assert!(!state.recv.contains_key(&id));
    assert!(!state.send.contains_key(&id));
    assert_eq!(state.max_remote[Dir::Bi as usize], 5);
    state.received_stop_sending(id, 9u32.into());
    state.received_max_stream_data(id, 19).unwrap();
    receive(&mut state, id, true);
    state.materialize_remote(id);
    assert!(!state.recv.contains_key(&id));
    assert!(!state.send.contains_key(&id));
    assert_eq!(state.max_remote[Dir::Bi as usize], 5);
}

#[test]
fn vole_lazy_closed_send_half_keeps_receive_half_and_single_credit() {
    let mut state = make(4);
    let id = StreamId::new(Side::Server, Dir::Bi, 0);
    state.received_max_stream_data(id, 17).unwrap();
    let connection = ConnState::Established;
    assert_eq!(
        (Streams {
            state: &mut state,
            conn_state: &connection
        })
        .accept(Dir::Bi),
        Some(id)
    );
    let mut pending = Retransmits::default();
    (SendStream {
        id,
        state: &mut state,
        pending: &mut pending,
        conn_state: &connection,
    })
    .reset(0u32.into())
    .unwrap();
    state.reset_acked(id);
    state.received_max_stream_data(id, 19).unwrap();
    state.received_stop_sending(id, 9u32.into());
    assert!(!state.send.contains_key(&id));
    assert!(state.recv.contains_key(&id));
    assert_eq!(state.max_remote[Dir::Bi as usize], 4);
    receive(&mut state, id, true);
    (RecvStream {
        id,
        state: &mut state,
        pending: &mut pending,
    })
    .stop(0u32.into())
    .unwrap();
    assert!(!state.recv.contains_key(&id));
    assert!(!state.send.contains_key(&id));
    assert_eq!(state.max_remote[Dir::Bi as usize], 5);
    assert_eq!(state.send_streams, 0);
}

#[test]
fn vole_lazy_credit_growth_and_exhaustion_remain_sparse() {
    let mut state = make(0);
    for dir in Dir::iter() {
        state.set_max_concurrent(dir, VarInt::from_u64(MAX_STREAM_COUNT).unwrap());
        assert_eq!(state.max_remote[dir as usize], MAX_STREAM_COUNT);
        assert_eq!(state.unmaterialized_remote[dir as usize].len(), 1);
    }
    assert!(state.send.is_empty());
    assert!(state.recv.is_empty());
    let id = StreamId::new(Side::Server, Dir::Uni, 0);
    receive(&mut state, id, true);
    let mut pending = Retransmits::default();
    (RecvStream {
        id,
        state: &mut state,
        pending: &mut pending,
    })
    .stop(0u32.into())
    .unwrap();
    assert_eq!(state.max_remote[Dir::Uni as usize], MAX_STREAM_COUNT);
    assert_eq!(
        state.allocated_remote_count[Dir::Uni as usize],
        MAX_STREAM_COUNT - 1
    );
    assert!(state.queue_max_stream_id(&mut pending));
    let mut encoded = Vec::new();
    state.write_control_frames(
        &mut encoded,
        &mut pending,
        &mut ThinRetransmits::default(),
        &mut FrameStats::default(),
        4096,
    );
    let frames: Vec<_> = frame::Iter::new(Bytes::from(encoded))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(frames.iter().filter(|frame| matches!(frame, frame::Frame::MaxStreams { count, .. } if *count == MAX_STREAM_COUNT)).count(), 2);
    assert!(frames.iter().all(|frame| !matches!(frame, frame::Frame::MaxStreams { count, .. } if *count > MAX_STREAM_COUNT)));
    assert_eq!(state.unmaterialized_remote[Dir::Uni as usize].len(), 1);
    assert!(state.recv.is_empty());
    assert_eq!(state.free_recv.len(), 1);

    let mut state = make(2);
    let id = StreamId::new(Side::Server, Dir::Uni, 0);
    receive(&mut state, id, true);
    state.set_max_concurrent(Dir::Uni, 1u32.into());
    (RecvStream {
        id,
        state: &mut state,
        pending: &mut pending,
    })
    .stop(0u32.into())
    .unwrap();
    assert_eq!(
        state.max_remote[Dir::Uni as usize],
        2,
        "shrink does not revoke advertised IDs"
    );
    state.set_max_concurrent(Dir::Uni, 3u32.into());
    assert_eq!(state.max_remote[Dir::Uni as usize], 4);
    assert!(state.unmaterialized_remote[Dir::Uni as usize].contains(3));
    assert!(!state.unmaterialized_remote[Dir::Uni as usize].contains(0));
    assert!(state.recv.is_empty());
}

#[test]
fn vole_lazy_zero_rtt_params_update_only_materialized_send_halves() {
    let mut state = make(MAX_STREAM_COUNT);
    let params = TransportParameters {
        initial_max_streams_bidi: 2u32.into(),
        initial_max_data: 4096u32.into(),
        initial_max_stream_data_bidi_local: 9u32.into(),
        initial_max_stream_data_bidi_remote: 11u32.into(),
        ..TransportParameters::default()
    };
    state.set_params(&params);
    let connection = ConnState::Established;
    let local = (Streams {
        state: &mut state,
        conn_state: &connection,
    })
    .open(Dir::Bi)
    .unwrap();
    let remote = StreamId::new(Side::Server, Dir::Bi, 0);
    state.received_max_stream_data(remote, 99).unwrap();
    assert_eq!(state.send[&remote].as_ref().unwrap().max_data, 99);
    state.set_params(&TransportParameters {
        initial_max_stream_data_bidi_local: 7u32.into(),
        ..params
    });
    assert_eq!(state.send[&remote].as_ref().unwrap().max_data, 7);
    state.zero_rtt_rejected();
    assert!(!state.send.contains_key(&local));
    assert!(!state.recv.contains_key(&local));
    assert_eq!(state.next[Dir::Bi as usize], 0);
    assert!(state.send.contains_key(&remote));
    assert!(state.unmaterialized_remote[Dir::Bi as usize].contains(1));
    let remote_next = StreamId::new(Side::Server, Dir::Bi, 1);
    state.received_max_stream_data(remote_next, 1).unwrap();
    assert_eq!(state.send[&remote_next].as_ref().unwrap().max_data, 7);
    assert_eq!(state.send.len(), 2);
    assert_eq!(state.recv.len(), 2);
}
