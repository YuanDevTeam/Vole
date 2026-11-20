// Memory-only shared collector cancellation and metadata script controls.
// Real shared collection, cancellation, script backend and final Bytes owner.
use super::*;
use std::sync::{Arc, atomic::AtomicUsize};
use tokio::io::{AsyncRead, BufReader, ReadBuf};
use tokio::sync::Notify;
use tokio::time::timeout;

// Observe actual source reads without retaining a payload or changing reads.
struct SourceProgress<R> {
    inner: R,
    read: Arc<AtomicUsize>,
    changed: Arc<Notify>,
}
impl<R: AsyncRead + Unpin> AsyncRead for SourceProgress<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) {
            let count = buffer.filled().len() - before;
            if count != 0 {
                this.read.fetch_add(count, Ordering::AcqRel);
                this.changed.notify_one();
            }
        }
        result
    }
}

#[tokio::test(flavor = "current_thread")]
async fn known_h1_shared_collection_cancels_after_64k_and_joins_before_refund() {
    const LENGTH: usize = 128 * 1024;
    const PREFIX: usize = 64 * 1024;
    let budget = body::Budget::default();
    let cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
    let read = Arc::new(AtomicUsize::new(0));
    let changed = Arc::new(Notify::new());
    let stop = CancellationToken::new();
    let child_stop = stop.clone();
    let child_budget = budget.clone();
    let child_read = read.clone();
    let child_changed = changed.clone();
    let (mut writer, source) = tokio::io::duplex(4096);
    let mut owner = tokio::spawn(async move {
        let mut reader = BufReader::new(SourceProgress {
            inner: source,
            read: child_read.clone(),
            changed: child_changed,
        });
        let url = Url::parse("https://shared-cancel.invalid/body").unwrap();
        let mut fields = vec![
            ("Content-Length".into(), LENGTH.to_string()),
            ("X-Independent".into(), "kept".into()),
        ];
        let before = fields.clone();
        let meta = OriginalRequestMeta::new("GET", &fields);
        let wire = WireBodyMeta::new(
            &fields,
            &meta,
            Phase::Response,
            Some(200),
            Some(LENGTH as u64),
            false,
        );
        let transaction =
            Transaction::begin_shared(&child_budget, &[], &url, Phase::Response, &wire, true)
                .unwrap();
        let blocklist = HashSet::new();
        // Pending collection owns the actual complete known-capacity backing.
        // The original collector deadline is unchanged by the observer.
        let outcome = tokio::select! { biased;
            () = child_stop.cancelled() => Err(io::Error::from(io::ErrorKind::Interrupted)),
            result = prepare_shared(
                &mut reader, Body::Length(LENGTH as u64), &blocklist,
                Duration::from_secs(1), Some(transaction), &mut fields,
            ) => result.map(|_| ()),
        };
        // The selected future has dropped its real Transaction before these facts.
        let facts = (
            outcome.map_err(|error| error.kind()),
            fields == before,
            child_read.load(Ordering::Acquire),
            reader.buffer().len(),
        );
        drop(reader);
        facts
    });
    // No assertion before cleanup: timeout/error must still cancel and join.
    let observed = timeout(Duration::from_secs(5), async {
        writer.write_all(&vec![b'a'; PREFIX]).await?;
        loop {
            let change = changed.notified();
            if read.load(Ordering::Acquire) >= PREFIX {
                break;
            }
            change.await;
        }
        Ok::<_, io::Error>((!owner.is_finished(), budget.used()))
    })
    .await;
    stop.cancel();
    drop(writer);
    let joined = match timeout(Duration::from_secs(2), &mut owner).await {
        Ok(result) => result.map_err(|error| error.to_string()),
        Err(_) => {
            owner.abort();
            let _ = owner.await;
            Err("collector owner needed fallback abort and was actually joined".into())
        }
    };
    let remaining = budget.used();
    let (pending, charged) = observed
        .expect("fixed memory harness deadline")
        .expect("real source prefix delivery");
    let (result, unchanged, source_reads, buffered) = joined.expect("collector actually joined");
    assert!(pending, "an incomplete known body must still be collecting");
    assert_eq!(charged, cost);
    assert_eq!(result, Err(io::ErrorKind::Interrupted));
    assert!(unchanged, "incomplete collection must not commit headers");
    assert_eq!(source_reads, PREFIX);
    assert_eq!(
        buffered, 0,
        "the observed source prefix was consumed by the collector"
    );
    assert_eq!(
        remaining, 0,
        "real collector/IO owner must drop before final refund"
    );
}

#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "current_thread")]
async fn shared_native_64k_then_real_metadata_script_keeps_body_owner_through_send() {
    const LENGTH: usize = 64 * 1024;
    let policy = Policy::compile(r#"rewrite:
  enabled: true
  rules:
    - {url: 'https://shared-meta.invalid/body', match: exact, action: request-body-replace, search: a, replacement: b}
http-scripts:
  enabled: true
  scripts:
    - name: real-metadata-after-native
      phase: request
      match: exact
      url: https://shared-meta.invalid/body
      body: none
      source: 'function rewrite(input){if(!input.body || input.body.kind !== "not-requested"){return {type:"abort"};}return {type:"modify",headers:[{op:"set",name:"x-meta",values:["after-native"]}]};}'
"#).unwrap();
    let budget = policy.body_budget();
    let url = Url::parse("https://shared-meta.invalid/body").unwrap();
    let original_fields = vec![
        ("Content-Type".into(), "text/plain".into()),
        ("Content-Length".into(), LENGTH.to_string()),
    ];
    let mut fields = original_fields.clone();
    let meta = OriginalRequestMeta::new("POST", &original_fields);
    let wire = WireBodyMeta::new(
        &original_fields,
        &meta,
        Phase::Request,
        None,
        Some(LENGTH as u64),
        false,
    );
    // This is the real false+native admission used with body:none scripts.
    assert!(
        policy
            .scripts()
            .iter()
            .all(|script| script.body == BodyMode::None)
    );
    let transaction =
        Transaction::begin_shared(budget, policy.rules(), &url, Phase::Request, &wire, false)
            .unwrap();
    let mut input = vec![b'a'; LENGTH];
    input.extend_from_slice(b"NEXT");
    let mut reader = input.as_slice();
    let (mut prepared, entity) = prepare_shared(
        &mut reader,
        Body::Length(LENGTH as u64),
        &HashSet::new(),
        Duration::from_secs(1),
        Some(transaction),
        &mut fields,
    )
    .await
    .unwrap();
    let entity = entity.expect("actual native shared collection completed");
    assert!(entity.changed() && entity.bypass.is_none());
    assert_eq!(entity.logical().unwrap(), vec![b'b'; LENGTH]);
    assert_eq!(reader, b"NEXT");
    let native_owner = entity.wire().clone();
    let native_pointer = native_owner.as_ptr();
    let cost = BudgetedBytes::allocation_cost(LENGTH).unwrap();
    assert_eq!(budget.used(), cost);
    let mut message = script_message::Message::request(
        OriginalSnapshot {
            url: url.clone(),
            method: "POST".into(),
            identity_allowed: meta.identity_allowed,
            asterisk: false,
        },
        RequestSnapshot {
            url: url.clone(),
            method: "POST".into(),
            headers: fields,
        },
        Some(entity),
        &original_fields,
        false,
    );
    let outcome = script_message::run(&policy, &url, &mut message, &CancellationToken::new())
        .await
        .unwrap();
    assert!(matches!(outcome, Outcome::Forward));
    assert!(
        message.request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-meta") && value == "after-native"
        }),
        "the real body:none backend must have changed the ordinary header"
    );
    let final_entity = message
        .body
        .take()
        .expect("metadata script preserved native body");
    assert_eq!(final_entity.wire().as_ptr(), native_pointer);
    assert_eq!(final_entity.logical().unwrap(), vec![b'b'; LENGTH]);
    assert_eq!(
        budget.used(),
        cost,
        "metadata-only execution must not retain another body"
    );
    let last = final_entity.wire().slice(LENGTH - 1..);
    prepared.install_entity(final_entity);
    drop(message);
    let mut sent = Vec::new();
    prepared
        .transfer(
            &mut reader,
            &mut sent,
            Duration::from_secs(1),
            &HashSet::new(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(sent, vec![b'b'; LENGTH]);
    assert_eq!(reader, b"NEXT");
    assert_eq!(native_owner.as_ref(), sent);
    assert_eq!(budget.used(), cost);
    drop(native_owner);
    assert_eq!(last.as_ref(), b"b");
    assert_eq!(
        budget.used(),
        cost,
        "the final real slice still owns the full charge"
    );
    drop(last);
    assert_eq!(budget.used(), 0);
}
