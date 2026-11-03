//! One native frame at a time, with credit returned after bounded forwarding.
use super::{
    body::{Bypass, Transaction},
    h2_headers, headers,
};
use bytes::Bytes;
use http::HeaderMap;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Duration, timeout};
pub(super) const IDLE: Duration = Duration::from_secs(30);

enum Kind {
    H2 {
        source: h2::RecvStream,
        trailers: bool,
    },
    H1(hyper::body::Incoming),
    Buffered {
        data: Option<Bytes>,
        trailers: Option<HeaderMap>,
    },
}

/// The same bounded body owner feeds both native H2 DATA and Hyper's HTTP/1
/// upload. Receive credit follows the current frame, never a detached task.
pub(super) struct Source {
    kind: Kind,
    prefix: Option<Bytes>,
    pending: Option<Bytes>,
    credit: usize,
    pending_credit: usize,
}
impl Source {
    pub(super) fn h2(source: h2::RecvStream) -> Self {
        Self {
            kind: Kind::H2 {
                source,
                trailers: false,
            },
            prefix: None,
            pending: None,
            credit: 0,
            pending_credit: 0,
        }
    }
    pub(super) fn h1(source: hyper::body::Incoming) -> Self {
        Self {
            kind: Kind::H1(source),
            prefix: None,
            pending: None,
            credit: 0,
            pending_credit: 0,
        }
    }
    fn buffered(data: Bytes, trailers: Option<HeaderMap>) -> Self {
        Self {
            kind: Kind::Buffered {
                data: Some(data),
                trailers,
            },
            prefix: None,
            pending: None,
            credit: 0,
            pending_credit: 0,
        }
    }
    fn release(&mut self) -> io::Result<()> {
        let credit = std::mem::take(&mut self.credit);
        if credit != 0
            && let Kind::H2 { source, .. } = &mut self.kind
        {
            source
                .flow_control()
                .release_capacity(credit)
                .map_err(|_| failed())?;
        }
        Ok(())
    }
    fn rewind(&mut self, prefix: Bytes, remaining: Bytes) -> io::Result<()> {
        if self.credit != 0 {
            let used = self
                .credit
                .checked_sub(remaining.len())
                .ok_or_else(failed)?;
            if let Kind::H2 { source, .. } = &mut self.kind {
                source
                    .flow_control()
                    .release_capacity(used)
                    .map_err(|_| failed())?;
            }
            self.pending_credit = remaining.len();
            self.credit = 0;
        }
        self.prefix = Some(prefix);
        if !remaining.is_empty() {
            self.pending = Some(remaining);
        }
        Ok(())
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        let _ = self.release();
        if self.pending_credit != 0
            && let Kind::H2 { source, .. } = &mut self.kind
        {
            let _ = source.flow_control().release_capacity(self.pending_credit);
        }
    }
}
impl Body for Source {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        if let Err(error) = self.release() {
            return Poll::Ready(Some(Err(error)));
        }
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        if let Some(pending) = self.pending.take() {
            self.credit = std::mem::take(&mut self.pending_credit);
            return Poll::Ready(Some(Ok(Frame::data(pending))));
        }
        match &mut self.kind {
            Kind::Buffered { data, trailers } => {
                if let Some(data) = data.take() {
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                Poll::Ready(
                    trailers
                        .take()
                        .map(|trailers| Ok(Frame::trailers(trailers))),
                )
            }
            Kind::H1(source) => Pin::new(source)
                .poll_frame(cx)
                .map(|value| value.map(|result| result.map_err(|_| failed()))),
            Kind::H2 { source, trailers } => {
                if !*trailers {
                    match source.poll_data(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Some(Ok(data))) => {
                            let count = data.len();
                            self.credit = count;
                            return Poll::Ready(Some(Ok(Frame::data(data))));
                        }
                        Poll::Ready(Some(Err(_))) => return Poll::Ready(Some(Err(failed()))),
                        Poll::Ready(None) => *trailers = true,
                    }
                }
                source.poll_trailers(cx).map(|result| match result {
                    Ok(trailers) => trailers.map(|trailers| Ok(Frame::trailers(trailers))),
                    Err(_) => Some(Err(failed())),
                })
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        if self.prefix.is_some() || self.pending.is_some() {
            return false;
        }
        match &self.kind {
            Kind::H2 { source, .. } => source.is_end_stream(),
            Kind::H1(source) => source.is_end_stream(),
            Kind::Buffered { data, trailers } => {
                data.as_ref().is_none_or(Bytes::is_empty) && trailers.is_none()
            }
        }
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::new()
    }
}

pub(super) struct Prepared {
    pub(super) source: Source,
    pub(super) expected: Option<u64>,
}

pub(super) async fn prepare(
    mut source: Source,
    mut transaction: Transaction<'_>,
    expected: Option<u64>,
    strip_credentials: bool,
    headers: &mut HeaderMap,
) -> io::Result<Prepared> {
    let mut length = Length::new(expected);
    let mut trailers = None;
    while let Some(frame) = timeout(
        IDLE,
        futures_util::future::poll_fn(|cx| Pin::new(&mut source).poll_frame(cx)),
    )
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
    {
        let frame = frame?;
        match frame.into_data() {
            Ok(mut data) => {
                length.consume(data.len())?;
                let count = transaction.remaining().min(data.len());
                let prefix = data.split_to(count);
                let result = transaction.push(&prefix);
                if result.is_err() || !data.is_empty() {
                    source.rewind(transaction.into_raw().into_bytes(), data)?;
                    return Ok(Prepared { source, expected });
                }
            }
            Err(frame) => {
                if let Ok(headers) = frame.into_trailers() {
                    trailers = Some(h2_headers::trailers(headers, strip_credentials)?);
                    break;
                }
            }
        }
    }
    length.finish()?;
    let mut result = transaction.finish(trailers.is_some());
    if result.changed {
        if let Some(mut fields) = headers::from_map(headers) {
            result.finalize_headers(&mut fields);
            if result.changed {
                *headers = headers::to_map(fields).ok_or_else(failed)?;
            }
        } else {
            result.rollback(Bypass::Budget);
        }
    }
    let expected = if result.changed {
        Some(result.body.as_ref().len() as u64)
    } else {
        expected
    };
    Ok(Prepared {
        source: Source::buffered(result.body.into_bytes(), trailers),
        expected,
    })
}
fn failed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "HTTP stream failed")
}
pub(super) struct Length(Option<u64>);
impl Length {
    pub(super) fn new(length: Option<u64>) -> Self {
        Self(length)
    }
    pub(super) fn remaining(&self) -> Option<u64> {
        self.0
    }
    pub(super) fn consume(&mut self, count: usize) -> io::Result<()> {
        if let Some(remaining) = self.0 {
            self.0 = Some(remaining.checked_sub(count as u64).ok_or_else(failed)?);
        }
        Ok(())
    }
    pub(super) fn finish(&self) -> io::Result<()> {
        if self.0.is_some_and(|remaining| remaining != 0) {
            Err(failed())
        } else {
            Ok(())
        }
    }
}
pub(super) async fn send_data(
    target: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
) -> io::Result<()> {
    while !data.is_empty() {
        target.reserve_capacity(data.len().min(16 * 1024));
        let available = timeout(
            IDLE,
            futures_util::future::poll_fn(|cx| target.poll_capacity(cx)),
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
        .ok_or_else(failed)?
        .map_err(|_| failed())?;
        if available == 0 {
            continue;
        }
        let count = data.len().min(available).min(16 * 1024);
        target
            .send_data(data.split_to(count), false)
            .map_err(|_| failed())?;
    }
    Ok(())
}
pub(super) fn finish(
    target: &mut h2::SendStream<Bytes>,
    trailers: Option<HeaderMap>,
    strip_credentials: bool,
) -> io::Result<()> {
    if let Some(trailers) = trailers {
        target
            .send_trailers(h2_headers::trailers(trailers, strip_credentials)?)
            .map_err(|_| failed())
    } else {
        target.send_data(Bytes::new(), true).map_err(|_| failed())
    }
}
pub(super) async fn relay(
    mut source: Source,
    mut target: h2::SendStream<Bytes>,
    expected: Option<u64>,
    strip_credentials: bool,
) -> io::Result<()> {
    let mut length = Length::new(expected);
    loop {
        let frame = timeout(
            IDLE,
            futures_util::future::poll_fn(|cx| Pin::new(&mut source).poll_frame(cx)),
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?;
        let Some(frame) = frame else {
            break;
        };
        match frame?.into_data() {
            Ok(data) => {
                length.consume(data.len())?;
                send_data(&mut target, data).await?;
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    length.finish()?;
                    return finish(&mut target, Some(trailers), strip_credentials);
                }
            }
        }
    }
    length.finish()?;
    finish(&mut target, None, strip_credentials)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_processing::{
        body::{Budget, MAX_BODY, OriginalRequestMeta, WireBodyMeta},
        rules::{Phase, RawRule, Rule},
    };
    use url::Url;

    fn rules() -> Vec<Rule> {
        let rule: RawRule =
            serde_yaml_ng::from_str("{url: '.', action: response-body-set, value: changed}")
                .unwrap();
        vec![Rule::compile(rule, &mut 0).unwrap()]
    }
    async fn drain(mut source: Source) -> (Vec<u8>, Option<HeaderMap>) {
        let mut output = Vec::new();
        let mut trailers = None;
        while let Some(frame) =
            futures_util::future::poll_fn(|cx| Pin::new(&mut source).poll_frame(cx)).await
        {
            match frame.unwrap().into_data() {
                Ok(data) => output.extend_from_slice(&data),
                Err(frame) => trailers = frame.into_trailers().ok(),
            }
        }
        (output, trailers)
    }
    #[tokio::test]
    async fn probe_replays_unknown_oversize_body_and_late_trailers() {
        let rules = rules();
        let url = Url::parse("https://a.example/").unwrap();
        let meta = OriginalRequestMeta::new("GET", &vec![]);
        let wire = WireBodyMeta::new(&vec![], &meta, Phase::Response, Some(200), None, false);
        let budget = Budget::default();
        let payload = Bytes::from(vec![b'a'; MAX_BODY + 500]);
        let transaction =
            Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
        let prepared = prepare(
            Source::buffered(payload.clone(), None),
            transaction,
            None,
            false,
            &mut HeaderMap::new(),
        )
        .await
        .unwrap();
        assert!(budget.used() > MAX_BODY);
        let (replayed, trailers) = drain(prepared.source).await;
        assert_eq!(replayed, payload);
        assert!(trailers.is_none());
        assert_eq!(budget.used(), 0);

        let mut trailers = HeaderMap::new();
        trailers.insert("x-final", "kept".parse().unwrap());
        let transaction =
            Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
        let prepared = prepare(
            Source::buffered(Bytes::from_static(b"original"), Some(trailers)),
            transaction,
            None,
            false,
            &mut HeaderMap::new(),
        )
        .await
        .unwrap();
        let (body, trailers) = drain(prepared.source).await;
        assert_eq!(body, b"original");
        assert_eq!(trailers.unwrap()["x-final"], "kept");
        assert_eq!(budget.used(), 0);
    }
    #[tokio::test]
    async fn probe_never_masks_truncated_body_as_rewrite_success() {
        let rules = rules();
        let url = Url::parse("https://a.example/").unwrap();
        let meta = OriginalRequestMeta::new("GET", &vec![]);
        let wire = WireBodyMeta::new(&vec![], &meta, Phase::Response, Some(200), Some(8), false);
        let budget = Budget::default();
        let transaction =
            Transaction::begin(&budget, &rules, &url, Phase::Response, &wire).unwrap();
        assert!(
            prepare(
                Source::buffered(Bytes::from_static(b"half"), None),
                transaction,
                Some(8),
                false,
                &mut HeaderMap::new()
            )
            .await
            .is_err()
        );
        assert_eq!(budget.used(), 0);
    }
}
