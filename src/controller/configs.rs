//! Thin Controller adapter; candidate ownership lives in the shared worker.
use super::*;
use crate::resource::config_apply::{ApplyError, ConfigApplyHandle, ConfigPatch, ConfigUpdate};
use serde::Deserialize;

const MAX_CONFIG_BODY: usize = 8 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineConfig {
    payload: String,
}

pub(super) async fn apply<S: ControllerIo>(
    stream: &mut S,
    request: crate::inbound::http::RequestHead,
    resources: Option<&dyn crate::resource::control::RuntimeResources>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let Some(handle) = resources.and_then(|resources| resources.config_apply()) else {
        return write_error(stream, 404, "Resource not found", &[]).await;
    };
    apply_with_handle(stream, request, handle, cancellation).await
}

pub(super) async fn maintenance<S: ControllerIo>(
    stream: &mut S,
    request: crate::inbound::http::RequestHead,
    resources: Option<&dyn crate::resource::control::RuntimeResources>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    if request.method != "POST" {
        return write_error(stream, 405, "Method not allowed", &[("Allow", "POST")]).await;
    }
    let mut lengths = header_values(&request.headers, "content-length");
    if lengths.next().is_some_and(|length| length != "0")
        || lengths.next().is_some()
        || header_values(&request.headers, "transfer-encoding")
            .next()
            .is_some()
        || !request.buffered.is_empty()
    {
        return write_error(stream, 400, "Body invalid", &[]).await;
    }
    let Some(handle) = resources.and_then(|resources| resources.config_apply()) else {
        return write_error(stream, 404, "Resource not found", &[]).await;
    };
    let admission = match handle.try_admit() {
        Ok(value) => value,
        Err(error) => return apply_error(stream, error).await,
    };
    let update = if request.target == "/configs/geo" {
        ConfigUpdate::RefreshGeoData
    } else {
        ConfigUpdate::FlushFakeIp
    };
    let pending = match admission.submit(update) {
        Ok(value) => value,
        Err(error) => return apply_error(stream, error).await,
    };
    let result = tokio::select! {biased;
        ()=cancellation.cancelled()=>return Ok(()),
        result=pending.wait()=>result,
    };
    match result {
        Ok(()) => write_response(stream, 204, &[], &[]).await,
        Err(error) => apply_error(stream, error).await,
    }
}

async fn apply_with_handle<S: ControllerIo>(
    stream: &mut S,
    request: crate::inbound::http::RequestHead,
    handle: ConfigApplyHandle,
    cancellation: CancellationToken,
) -> io::Result<()> {
    if !matches!(request.method.as_str(), "PATCH" | "PUT") {
        return write_error(
            stream,
            405,
            "Method not allowed",
            &[("Allow", "GET, PATCH, PUT")],
        )
        .await;
    }
    // Admission precedes extending the header reader's bounded prefix into a
    // full body, JSON allocation, parsing, or any worker preparation.
    let admission = match handle.try_admit() {
        Ok(value) => value,
        Err(error) => return apply_error(stream, error).await,
    };
    if header_values(&request.headers, "transfer-encoding")
        .next()
        .is_some()
    {
        return write_error(stream, 400, "Body invalid", &[]).await;
    }
    let mut types = header_values(&request.headers, "content-type");
    if !types
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
        || types.next().is_some()
    {
        return write_error(stream, 415, "Unsupported media type", &[]).await;
    }
    let mut lengths = header_values(&request.headers, "content-length");
    let Some(length) = lengths.next() else {
        return write_error(stream, 411, "Length required", &[]).await;
    };
    if lengths.next().is_some()
        || length.is_empty()
        || !length.bytes().all(|byte| byte.is_ascii_digit())
    {
        return write_error(stream, 400, "Body invalid", &[]).await;
    }
    let Ok(length) = length.parse::<usize>() else {
        return write_error(stream, 400, "Body invalid", &[]).await;
    };
    let limit = if request.method == "PUT" {
        MAX_CONFIG_BODY
    } else {
        MAX_CONTROLLER_BODY_BYTES
    };
    if length > limit {
        return write_error(stream, 413, "Payload too large", &[]).await;
    }
    let mut body = request.buffered;
    if body.len() > length {
        return write_error(stream, 400, "Body invalid", &[]).await;
    }
    let buffered = body.len();
    body.resize(length, 0);
    if buffered < length {
        let result = tokio::select! { biased;
            ()=cancellation.cancelled()=>return Ok(()),
            result=timeout(CONTROLLER_BODY_TIMEOUT,stream.read_exact(&mut body[buffered..]))=>result,
        };
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return write_error(stream, 400, "Body invalid", &[]).await,
            Err(_) => return write_error(stream, 408, "Timeout", &[]).await,
        }
    }
    let update = if request.method == "PUT" {
        match serde_json::from_slice::<InlineConfig>(&body) {
            Ok(config) if !config.payload.is_empty() => ConfigUpdate::Replace(config.payload),
            _ => return write_error(stream, 400, "Body invalid", &[]).await,
        }
    } else {
        match serde_json::from_slice::<ConfigPatch>(&body) {
            Ok(patch) => ConfigUpdate::Patch(patch),
            Err(_) => return write_error(stream, 400, "Body invalid", &[]).await,
        }
    };
    drop(body);
    let pending = match admission.submit(update) {
        Ok(value) => value,
        Err(error) => return apply_error(stream, error).await,
    };
    // Cancellation/timeout of this wait cancels the candidate. A normal HTTP
    // request half-close is not interpreted as candidate cancellation.
    let result = tokio::select! {biased;
        ()=cancellation.cancelled()=>return Ok(()),
        result=pending.wait()=>result,
    };
    match result {
        Ok(()) => write_response(stream, 204, &[], &[]).await,
        Err(error) => apply_error(stream, error).await,
    }
}

pub(super) async fn apply_error<S: ControllerIo>(
    stream: &mut S,
    error: ApplyError,
) -> io::Result<()> {
    let status = match error {
        ApplyError::InvalidConfig => 400,
        ApplyError::RestartRequired => 409,
        ApplyError::TimedOut => 504,
        ApplyError::Busy | ApplyError::Stopped | ApplyError::PreparationFailed => 503,
    };
    write_error(stream, status, error.message(), &[]).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    fn request(body: &str) -> crate::inbound::http::RequestHead {
        crate::inbound::http::RequestHead {
            method: "PUT".into(),
            target: "/configs".into(),
            version: "HTTP/1.1".into(),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("content-length".into(), body.len().to_string()),
            ],
            buffered: body.as_bytes().to_vec(),
        }
    }
    async fn run(body: &str, expected: Option<&str>, completion: Result<(), ApplyError>) -> String {
        let cancellation = CancellationToken::new();
        let (handle, mut receiver) = ConfigApplyHandle::channel(cancellation.clone());
        let (mut client, server) = tokio::io::duplex(4096);
        let request = request(body);
        let expected = expected.map(str::to_owned);
        let worker = tokio::spawn(async move {
            if let Some(expected) = expected {
                let mut task = receiver.recv().await.unwrap();
                assert!(
                    matches!(task.take_update(),ConfigUpdate::Replace(value) if value==expected)
                );
                task.complete(completion);
            }
        });
        let controller = tokio::spawn(async move {
            apply_with_handle(&mut H1Io(server), request, handle, cancellation)
                .await
                .unwrap();
        });
        let mut result = String::new();
        client.read_to_string(&mut result).await.unwrap();
        controller.await.unwrap();
        worker.await.unwrap();
        result
    }
    #[tokio::test]
    async fn inline_update_is_shared_and_candidate_failure_has_a_fixed_response() {
        assert!(
            run(
                r#"{"payload":"rules: [MATCH,DIRECT]"}"#,
                Some("rules: [MATCH,DIRECT]"),
                Ok(())
            )
            .await
            .starts_with("HTTP/1.1 204")
        );
        let failure = run(
            r#"{"payload":"private credentials"}"#,
            Some("private credentials"),
            Err(ApplyError::PreparationFailed),
        )
        .await;
        assert!(failure.starts_with("HTTP/1.1 503"));
        assert!(!failure.contains("private credentials"));
        assert!(
            run(r#"{"path":"/private/file"}"#, None, Ok(()))
                .await
                .starts_with("HTTP/1.1 400")
        );
    }
    #[tokio::test]
    async fn busy_admission_rejects_before_waiting_for_the_declared_body() {
        let cancel = CancellationToken::new();
        let (handle, _receiver) = ConfigApplyHandle::channel(cancel.clone());
        let _occupied = handle.try_admit().unwrap();
        let (mut client, server) = tokio::io::duplex(1024);
        let mut request = request("");
        request.headers[1].1 = MAX_CONFIG_BODY.to_string();
        let task = tokio::spawn(async move {
            apply_with_handle(&mut H1Io(server), request, handle, cancel)
                .await
                .unwrap()
        });
        let mut result = String::new();
        timeout(Duration::from_secs(1), client.read_to_string(&mut result))
            .await
            .unwrap()
            .unwrap();
        task.await.unwrap();
        assert!(result.starts_with("HTTP/1.1 503"));
    }
}
