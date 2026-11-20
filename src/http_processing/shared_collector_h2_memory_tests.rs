// Real shared collector and Length/frame handling through Source::Buffered.
// This is not a wire/RecvStream flow-credit test; that boundary stays explicit.
use super::*;

fn shared_h2_wire(length: Option<u64>) -> WireBodyMeta {
    let meta = OriginalRequestMeta::new("GET", &vec![]);
    WireBodyMeta::new(&vec![], &meta, Phase::Response, Some(200), length, false)
}

#[tokio::test]
async fn shared_h2_64k_length_completion_and_errors_preserve_atomicity() {
    let url = Url::parse("https://shared-h2.invalid/body").unwrap();
    for actual in [65535, 65536, 65537] {
        let budget = Budget::default();
        let wire = shared_h2_wire(Some(65536));
        let transaction =
            Transaction::begin_shared(&budget, &[], &url, Phase::Response, &wire, true).unwrap();
        let mut fields = vec![
            ("Content-Length".into(), "65536".into()),
            ("X-Independent".into(), "kept".into()),
        ];
        let before = fields.clone();
        let result = prepare_shared(
            Source::buffered(Bytes::from(vec![b'a'; actual]), None),
            transaction,
            Some(65536),
            false,
            &mut fields,
        )
        .await;
        assert_eq!(fields, before);
        if actual == 65536 {
            let prepared = result.expect("exact complete shared frame body");
            assert_eq!(prepared.expected, Some(65536));
            let entity = prepared.entity.expect("actual collected entity");
            assert_eq!(entity.logical().unwrap(), vec![b'a'; 65536]);
            let last = entity.wire().slice(65535..);
            drop(entity);
            let (body, trailers) = drain(prepared.source).await;
            assert_eq!(body, vec![b'a'; 65536]);
            assert!(trailers.is_none());
            assert_eq!(last.as_ref(), b"a");
            assert_eq!(
                budget.used(),
                crate::http_processing::body::BudgetedBytes::allocation_cost(65536).unwrap()
            );
            drop(last);
        } else {
            let error = result
                .err()
                .expect("real Length rejects short/oversized body");
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        }
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn shared_h2_unknown_overflow_replays_prefix_remaining_frame_and_trailers() {
    let budget = Budget::default();
    let url = Url::parse("https://shared-h2.invalid/body").unwrap();
    let wire = shared_h2_wire(None);
    let transaction =
        Transaction::begin_shared(&budget, &[], &url, Phase::Response, &wire, true).unwrap();
    let payload = Bytes::from(vec![b'a'; MAX_BODY + 123]);
    let mut trailers = HeaderMap::new();
    trailers.insert("x-final", "kept".parse().unwrap());
    let mut fields = vec![("X-Independent".into(), "kept".into())];
    let before = fields.clone();
    let prepared = prepare_shared(
        Source::buffered(payload.clone(), Some(trailers)),
        transaction,
        None,
        false,
        &mut fields,
    )
    .await
    .unwrap();
    assert!(prepared.entity.is_none());
    assert_eq!(prepared.expected, None);
    assert_eq!(fields, before);
    let prefix = prepared
        .source
        .prefix
        .as_ref()
        .expect("collected MAX_BODY+1 sentinel");
    assert_eq!(prefix.len(), MAX_BODY + 1);
    assert_eq!(prepared.source.pending.as_ref().unwrap().len(), 122);
    assert_eq!(
        budget.used(),
        crate::http_processing::body::BudgetedBytes::allocation_cost(MAX_BODY + 1).unwrap()
    );
    let (replayed, trailers) = drain(prepared.source).await;
    assert_eq!(replayed, payload);
    assert_eq!(trailers.unwrap()["x-final"], "kept");
    assert_eq!(budget.used(), 0);
}
