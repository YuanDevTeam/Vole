//! The Android sandbox runs the same prelude as the native engines, with
//! body bytes carried outside evaluation source and result JSON.

use super::CompiledSource;
use crate::{
    ffi::android::js,
    http_processing::body_budget::{BudgetedBytes, MAX_BODY, Reservation},
};
use serde_json::Value;
use std::{io, time::Instant};
use tokio_util::sync::CancellationToken;

const MAX_INPUT_METADATA: usize = 1024 * 1024;

pub(super) fn ensure_available() -> io::Result<()> {
    js::ensure_available()
}

pub(super) fn initialize_platform() -> io::Result<()> {
    js::prepare()
}

pub(super) fn shutdown_platform() -> io::Result<()> {
    js::shutdown()
}

pub(super) fn bridge_cost(input: usize, text: bool, output: usize) -> Option<usize> {
    if input > MAX_BODY || output > MAX_BODY {
        return None;
    }
    // The original entity and the Rust committed output have their own
    // charges. Count the JNI byte[], pipe/Binder staging, service byte[]
    // and ArrayBuffer, plus two UTF-16 copies and bounded decoder scratch
    // for text input. Output covers a separate export ArrayBuffer and the
    // reverse transport up to and including the native callback's Vec.
    let inbound = input.checked_mul(if text { 8 } else { 4 })?;
    let outbound = output.checked_mul(5)?;
    let codec_scratch = if text && input != 0 { 32 * 1024 } else { 0 };
    inbound.checked_add(outbound)?.checked_add(codec_scratch)
}

pub(super) fn evaluate(
    program: &CompiledSource,
    metadata: &Value,
    input: Option<&[u8]>,
    output: &mut BudgetedBytes,
    bridge_workspace: Option<&Reservation>,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> io::Result<Value> {
    check(cancellation, deadline)?;
    let input_length = input.map_or(0, <[u8]>::len);
    let output_bound = program.maximum_output_bytes(input_length);
    let text = metadata["body"]["kind"] == "text";
    let bridge_bytes = bridge_cost(input_length, text, output_bound).ok_or_else(invalid)?;
    let _local_bridge = if let Some(prepaid) = bridge_workspace {
        if !prepaid.covers(output, bridge_bytes) {
            return Err(invalid());
        }
        None
    } else if bridge_bytes != 0 {
        Some(
            output
                .reserve_temporary(bridge_bytes)
                .ok_or(io::ErrorKind::OutOfMemory)?,
        )
    } else {
        None
    };
    let script = source(program, metadata, input.is_some(), output_bound)?;
    let result = js::evaluate(
        script.as_bytes(),
        input.unwrap_or_default(),
        output_bound,
        cancellation,
        deadline,
    )?;
    let value: Value = serde_json::from_slice(&result.metadata).map_err(|_| invalid())?;
    match value.get("body") {
        Some(body) => {
            match body.get("kind").and_then(Value::as_str) {
                Some("text") => {
                    std::str::from_utf8(&result.body).map_err(|_| invalid())?;
                }
                Some("bytes") => {}
                _ => return Err(invalid()),
            }
            output.prepare_output(result.body.len())?;
            output.extend(&result.body)?;
        }
        None if result.body.is_empty() => {}
        None => return Err(invalid()),
    }
    check(cancellation, deadline)?;
    Ok(value)
}

fn source(
    program: &CompiledSource,
    metadata: &Value,
    has_body: bool,
    output_bound: usize,
) -> io::Result<String> {
    let metadata = serde_json::to_string(metadata).map_err(|_| invalid())?;
    if metadata.len() > MAX_INPUT_METADATA {
        return Err(invalid());
    }
    // Quote the whole JSON string so metadata remains data, including
    // isolated substrings that would have a different object-literal meaning.
    let metadata = serde_json::to_string(&metadata).map_err(|_| invalid())?;
    let prelude = include_str!("runtime.js");
    let adapter = include_str!("android_transport.js");
    Ok(format!(
        "{prelude}\n{}\n{adapter}\n__voleTransport(JSON.parse({metadata}), {has_body}, {output_bound});",
        program.code
    ))
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Android JavaScript bridge data",
    )
}

fn check(cancellation: &CancellationToken, deadline: Instant) -> io::Result<()> {
    if cancellation.is_cancelled() {
        Err(io::ErrorKind::Interrupted.into())
    } else if Instant::now() >= deadline {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}
