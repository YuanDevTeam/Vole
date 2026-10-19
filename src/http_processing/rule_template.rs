//! Strict, prevalidated replacement templates with bounded expansion.
use regex::{Captures, Regex};
use std::io;

use super::invalid;

pub(super) struct Template {
    parts: Box<[Part]>,
    captures: bool,
}

enum Part {
    Literal(Box<str>),
    Capture(usize),
}

impl Template {
    pub(super) fn compile(input: &str, regex: &Regex) -> io::Result<Self> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut rest = input;
        let mut captures = false;
        while let Some(start) = rest.find('$') {
            if start != 0 {
                literal.push_str(&rest[..start]);
            }
            rest = &rest[start + 1..];
            if let Some(tail) = rest.strip_prefix('$') {
                literal.push('$');
                rest = tail;
                continue;
            }
            let name;
            if let Some(braced) = rest.strip_prefix('{') {
                let end = braced.find('}').ok_or_else(invalid)?;
                name = &braced[..end];
                rest = &braced[end + 1..];
            } else {
                let end = rest.bytes().take_while(u8::is_ascii_digit).count();
                if end == 0 {
                    return Err(invalid());
                }
                name = &rest[..end];
                rest = &rest[end..];
            }
            if name.is_empty() {
                return Err(invalid());
            }
            let index = if name.bytes().all(|byte| byte.is_ascii_digit()) {
                name.parse::<usize>().map_err(|_| invalid())?
            } else {
                regex
                    .capture_names()
                    .position(|entry| entry == Some(name))
                    .ok_or_else(invalid)?
            };
            if index >= regex.captures_len() {
                return Err(invalid());
            }
            if !literal.is_empty() {
                parts.push(Part::Literal(std::mem::take(&mut literal).into()));
            }
            parts.push(Part::Capture(index));
            captures = true;
        }
        literal.push_str(rest);
        if !literal.is_empty() {
            parts.push(Part::Literal(literal.into()));
        }
        Ok(Self {
            parts: parts.into(),
            captures,
        })
    }

    pub(super) fn constant(&self, limit: usize) -> io::Result<Option<String>> {
        if self.captures {
            return Ok(None);
        }
        let mut out = String::new();
        for part in &self.parts {
            if let Part::Literal(value) = part {
                append(&mut out, value, limit)?;
            }
        }
        Ok(Some(out))
    }

    pub(super) fn append(
        &self,
        captures: &Captures<'_>,
        out: &mut String,
        limit: usize,
    ) -> io::Result<()> {
        for part in &self.parts {
            match part {
                Part::Literal(value) => append(out, value, limit)?,
                Part::Capture(index) => {
                    if let Some(value) = captures.get(*index) {
                        append(out, value.as_str(), limit)?;
                    }
                }
            }
        }
        Ok(())
    }
}

pub(super) fn append(out: &mut String, value: &str, limit: usize) -> io::Result<()> {
    if value.len() > limit.saturating_sub(out.len()) {
        return Err(invalid());
    }
    out.push_str(value);
    Ok(())
}
