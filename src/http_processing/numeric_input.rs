//! Reject YAML numeric scalars whose conversion would change a patch value.
//! This streaming pass retains the scalar spelling that serde's f64 visitor
//! otherwise discards. It runs only on bounded configuration inputs.
use super::config::invalid;
use std::io;
use yaml_rust2::{
    parser::{Event, Parser},
    scanner::TScalarStyle,
};

pub(super) fn validate(input: &[u8]) -> io::Result<()> {
    let input = std::str::from_utf8(input).map_err(|_| invalid())?;
    let mut parser = Parser::new_from_str(input);
    let mut depth = 0usize;
    loop {
        let (event, _) = parser.next_token().map_err(|_| invalid())?;
        match event {
            Event::MappingStart(..) | Event::SequenceStart(..) => {
                depth += 1;
                if depth > 64 {
                    return Err(invalid());
                }
            }
            Event::MappingEnd | Event::SequenceEnd => depth = depth.saturating_sub(1),
            Event::Scalar(raw, style, _, tag) => {
                let tag = tag
                    .as_ref()
                    .map(|tag| format!("{}{}", tag.handle, tag.suffix));
                let forced_float = tag.as_deref() == Some("tag:yaml.org,2002:float");
                if tag.is_some() && !forced_float || !forced_float && style != TScalarStyle::Plain {
                    continue;
                }
                let value = if forced_float {
                    raw.parse::<f64>()
                        .ok()
                        .map(|value| serde_yaml_ng::Value::Number(value.into()))
                } else {
                    serde_yaml_ng::from_str(&raw).ok()
                };
                if matches!(value, Some(serde_yaml_ng::Value::String(_)))
                    && decimal_spelling(&raw)
                    && !(raw.trim_start_matches(['-', '+']).starts_with('0')
                        && raw.trim_start_matches(['-', '+']).len() > 1
                        && !raw.contains(['.', 'e', 'E']))
                {
                    return Err(invalid());
                }
                if let Some(serde_yaml_ng::Value::Number(number)) = value
                    && (forced_float || !number.is_i64() && !number.is_u64())
                {
                    let converted = serde_json::to_string(&number).map_err(|_| invalid())?;
                    if decimal(&raw).is_none_or(|original| Some(original) != decimal(&converted)) {
                        return Err(invalid());
                    }
                }
            }
            Event::StreamEnd => return Ok(()),
            _ => {}
        }
    }
}

fn decimal(raw: &str) -> Option<(bool, String, i64)> {
    let raw = raw.replace('_', "");
    let negative = raw.starts_with('-');
    let raw = raw.strip_prefix(['-', '+']).unwrap_or(&raw);
    let (mantissa, exponent) = match raw.find(['e', 'E']) {
        Some(at) => (&raw[..at], raw[at + 1..].parse::<i64>().ok()?),
        None => (raw, 0),
    };
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if integer.is_empty() && fraction.is_empty()
        || !integer
            .bytes()
            .chain(fraction.bytes())
            .all(|v| v.is_ascii_digit())
    {
        return None;
    }
    let mut digits = format!("{integer}{fraction}");
    let mut exponent = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
    let leading = digits.bytes().take_while(|v| *v == b'0').count();
    digits.drain(..leading);
    if digits.is_empty() {
        return Some((false, "0".into(), 0));
    }
    while digits.ends_with('0') {
        digits.pop();
        exponent = exponent.checked_add(1)?;
    }
    Some((negative, digits, exponent))
}

fn decimal_spelling(raw: &str) -> bool {
    let raw = raw.replace('_', "");
    let raw = raw.trim_start_matches(['-', '+']);
    let (mantissa, exponent) = raw.split_once(['e', 'E']).unwrap_or((&raw, "0"));
    let exponent = exponent.strip_prefix(['-', '+']).unwrap_or(exponent);
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    (!integer.is_empty() || !fraction.is_empty())
        && integer
            .bytes()
            .chain(fraction.bytes())
            .all(|v| v.is_ascii_digit())
        && !exponent.is_empty()
        && exponent.bytes().all(|v| v.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scalar_conversion_never_silently_rounds_patch_numbers() {
        for input in [
            "x: 0.5",
            "x: 1.0",
            "x: 1e-6",
            "x: -0.0",
            "x: 0.12345678901234568",
            "x: '0.123456789012345678901'",
            "x: !!str 0.123456789012345678901",
            "x: !!float \"0.5\"",
        ] {
            assert!(validate(input.as_bytes()).is_ok(), "{input}");
        }
        for input in [
            "x: 0.123456789012345678901",
            "x: 340282366920938463463374607431768211457",
            "x: .nan",
            "x: .inf",
            "x: !!float \"0.123456789012345678901\"",
            "x: !!float 9007199254740993",
            "x: 1e309",
            "x: 1e9223372036854775808",
        ] {
            assert!(validate(input.as_bytes()).is_err(), "{input}");
        }
    }
}
