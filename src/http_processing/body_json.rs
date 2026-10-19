//! A small budgeted JSON tree and RFC 6902 adapter. Numbers retain their source
//! spelling; parsing never routes business JSON through an f64-backed Value.
use super::{Budget, BudgetedBytes, Bypass, MAX_BODY};
use crate::http_processing::rules::PatchOperation;
use std::io::Write;

const ARENA: usize = 256 * 1024;
const DEPTH: usize = 64;

enum Node {
    Null,
    Bool(bool),
    Number(Box<str>),
    String(Box<str>),
    Array(Vec<Node>),
    Object(Vec<(Box<str>, Node)>),
}
struct Arena {
    used: usize,
}
impl Arena {
    fn charge(&mut self, bytes: usize) -> Result<(), Bypass> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|value| *value <= ARENA)
            .ok_or(Bypass::Budget)?;
        Ok(())
    }
    fn room(&self, bytes: usize) -> Result<(), Bypass> {
        self.used
            .checked_add(bytes)
            .filter(|value| *value <= ARENA)
            .map(|_| ())
            .ok_or(Bypass::Budget)
    }
    fn text(&mut self, text: &str) -> Result<Box<str>, Bypass> {
        self.charge(text.len())?;
        Ok(text.into())
    }
    fn push<T>(&mut self, values: &mut Vec<T>, value: T) -> Result<(), Bypass> {
        if values.len() == values.capacity() {
            let next = values
                .capacity()
                .max(2)
                .checked_mul(2)
                .ok_or(Bypass::Budget)?;
            self.charge(
                next.checked_mul(std::mem::size_of::<T>())
                    .ok_or(Bypass::Budget)?,
            )?;
            values
                .try_reserve_exact(next - values.len())
                .map_err(|_| Bypass::Budget)?;
            if values.capacity() > next {
                return Err(Bypass::Budget);
            }
        }
        values.push(value);
        Ok(())
    }
}

struct Parser<'a> {
    text: &'a str,
    at: usize,
    arena: &'a mut Arena,
}
impl<'a> Parser<'a> {
    fn parse(text: &'a str, arena: &'a mut Arena) -> Result<Node, Bypass> {
        // RawValue validates syntax using the borrowed raw path, without first
        // constructing an unbudgeted serde_json::Value or rounding numbers.
        serde_json::from_str::<&serde_json::value::RawValue>(text)
            .map_err(|_| Bypass::Transform)?;
        let mut parser = Self { text, at: 0, arena };
        let value = parser.value(0)?;
        parser.white();
        if parser.at != text.len() {
            return Err(Bypass::Transform);
        }
        Ok(value)
    }
    fn white(&mut self) {
        while self
            .text
            .as_bytes()
            .get(self.at)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.at += 1;
        }
    }
    fn token(&mut self, token: &str) -> Result<(), Bypass> {
        if !self.text[self.at..].starts_with(token) {
            return Err(Bypass::Transform);
        }
        self.at += token.len();
        Ok(())
    }
    fn string(&mut self) -> Result<Box<str>, Bypass> {
        let start = self.at;
        self.token("\"")?;
        loop {
            match self.text.as_bytes().get(self.at) {
                Some(b'\\') => self.at += 2,
                Some(b'"') => {
                    self.at += 1;
                    break;
                }
                Some(_) => self.at += 1,
                None => return Err(Bypass::Transform),
            }
        }
        let raw = &self.text[start..self.at];
        // Covers the parser's escaped-string scratch, returned String, and
        // conversion to a tightly sized box before allocating any of them.
        self.arena
            .room(raw.len().checked_mul(3).ok_or(Bypass::Budget)?)?;
        let value: String = serde_json::from_str(raw).map_err(|_| Bypass::Transform)?;
        self.arena.charge(value.len())?;
        Ok(value.into_boxed_str())
    }
    fn value(&mut self, depth: usize) -> Result<Node, Bypass> {
        if depth > DEPTH {
            return Err(Bypass::Budget);
        }
        self.white();
        let value = match self.text.as_bytes().get(self.at).copied() {
            Some(b'n') => {
                self.token("null")?;
                Node::Null
            }
            Some(b't') => {
                self.token("true")?;
                Node::Bool(true)
            }
            Some(b'f') => {
                self.token("false")?;
                Node::Bool(false)
            }
            Some(b'"') => Node::String(self.string()?),
            Some(b'[') => {
                self.at += 1;
                self.white();
                let mut values = Vec::new();
                if self.text.as_bytes().get(self.at) != Some(&b']') {
                    loop {
                        let value = self.value(depth + 1)?;
                        self.arena.push(&mut values, value)?;
                        self.white();
                        if self.text.as_bytes().get(self.at) != Some(&b',') {
                            break;
                        }
                        self.at += 1;
                    }
                }
                self.token("]")?;
                Node::Array(values)
            }
            Some(b'{') => {
                self.at += 1;
                self.white();
                let mut values: Vec<(Box<str>, Node)> = Vec::new();
                if self.text.as_bytes().get(self.at) != Some(&b'}') {
                    loop {
                        self.white();
                        let key = self.string()?;
                        if values.iter().any(|(old, _)| *old == key) {
                            return Err(Bypass::Transform);
                        }
                        self.white();
                        self.token(":")?;
                        let value = self.value(depth + 1)?;
                        self.arena.push(&mut values, (key, value))?;
                        self.white();
                        if self.text.as_bytes().get(self.at) != Some(&b',') {
                            break;
                        }
                        self.at += 1;
                    }
                }
                self.token("}")?;
                Node::Object(values)
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.at;
                while self.text.as_bytes().get(self.at).is_some_and(|byte| {
                    matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                }) {
                    self.at += 1;
                }
                Node::Number(self.arena.text(&self.text[start..self.at])?)
            }
            _ => return Err(Bypass::Transform),
        };
        Ok(value)
    }
}

fn duplicate(value: &Node, arena: &mut Arena, depth: usize) -> Result<Node, Bypass> {
    if depth > DEPTH {
        return Err(Bypass::Budget);
    }
    Ok(match value {
        Node::Null => Node::Null,
        Node::Bool(value) => Node::Bool(*value),
        Node::Number(value) => Node::Number(arena.text(value)?),
        Node::String(value) => Node::String(arena.text(value)?),
        Node::Array(values) => {
            let mut result = Vec::new();
            for value in values {
                let value = duplicate(value, arena, depth + 1)?;
                arena.push(&mut result, value)?;
            }
            Node::Array(result)
        }
        Node::Object(values) => {
            let mut result = Vec::new();
            for (key, value) in values {
                let key = arena.text(key)?;
                let value = duplicate(value, arena, depth + 1)?;
                arena.push(&mut result, (key, value))?;
            }
            Node::Object(result)
        }
    })
}

fn pointer(path: &str, arena: &mut Arena) -> Result<Vec<Box<str>>, Bypass> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    if !path.starts_with('/') {
        return Err(Bypass::Transform);
    }
    let mut result = Vec::new();
    for piece in path[1..].split('/') {
        arena.room(piece.len().checked_mul(2).ok_or(Bypass::Budget)?)?;
        let mut value = String::with_capacity(piece.len());
        let mut chars = piece.chars();
        while let Some(character) = chars.next() {
            value.push(if character == '~' {
                match chars.next() {
                    Some('0') => '~',
                    Some('1') => '/',
                    _ => return Err(Bypass::Transform),
                }
            } else {
                character
            });
        }
        arena.charge(value.len())?;
        arena.push(&mut result, value.into_boxed_str())?;
    }
    if result.len() > DEPTH {
        return Err(Bypass::Budget);
    }
    Ok(result)
}

fn index(token: &str, length: usize, append: bool) -> Result<usize, Bypass> {
    if append && token == "-" {
        return Ok(length);
    }
    if token.is_empty()
        || (token.len() > 1 && token.starts_with('0'))
        || !token.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Bypass::Transform);
    }
    let index: usize = token.parse().map_err(|_| Bypass::Transform)?;
    if index > length || (!append && index == length) {
        return Err(Bypass::Transform);
    }
    Ok(index)
}
fn get<'a>(mut value: &'a Node, path: &[Box<str>]) -> Result<&'a Node, Bypass> {
    for token in path {
        value = match value {
            Node::Object(values) => {
                &values
                    .iter()
                    .find(|(key, _)| key == token)
                    .ok_or(Bypass::Transform)?
                    .1
            }
            Node::Array(values) => &values[index(token, values.len(), false)?],
            _ => return Err(Bypass::Transform),
        };
    }
    Ok(value)
}
fn get_mut<'a>(mut value: &'a mut Node, path: &[Box<str>]) -> Result<&'a mut Node, Bypass> {
    for token in path {
        value = match value {
            Node::Object(values) => {
                &mut values
                    .iter_mut()
                    .find(|(key, _)| key == token)
                    .ok_or(Bypass::Transform)?
                    .1
            }
            Node::Array(values) => {
                let i = index(token, values.len(), false)?;
                &mut values[i]
            }
            _ => return Err(Bypass::Transform),
        };
    }
    Ok(value)
}
fn add(root: &mut Node, path: &[Box<str>], value: Node, arena: &mut Arena) -> Result<(), Bypass> {
    let Some((token, parent)) = path.split_last() else {
        *root = value;
        return Ok(());
    };
    match get_mut(root, parent)? {
        Node::Object(values) => {
            if let Some((_, old)) = values.iter_mut().find(|(key, _)| key == token) {
                *old = value;
            } else {
                let key = arena.text(token)?;
                arena.push(values, (key, value))?;
            }
        }
        Node::Array(values) => {
            let at = index(token, values.len(), true)?;
            // Grow with the same charged allocation policy before insert.
            arena.push(values, Node::Null)?;
            values[at..].rotate_right(1);
            values[at] = value;
        }
        _ => return Err(Bypass::Transform),
    }
    Ok(())
}
fn remove(root: &mut Node, path: &[Box<str>]) -> Result<Node, Bypass> {
    let Some((token, parent)) = path.split_last() else {
        return Err(Bypass::Transform);
    };
    match get_mut(root, parent)? {
        Node::Object(values) => {
            let at = values
                .iter()
                .position(|(key, _)| key == token)
                .ok_or(Bypass::Transform)?;
            Ok(values.remove(at).1)
        }
        Node::Array(values) => {
            let at = index(token, values.len(), false)?;
            Ok(values.remove(at))
        }
        _ => Err(Bypass::Transform),
    }
}

// Add a bounded signed i64 adjustment to an arbitrarily long decimal exponent.
fn adjust_exponent(raw: &str, adjustment: i64) -> String {
    let negative = raw.starts_with('-');
    let digits = raw.trim_start_matches(['-', '+']).trim_start_matches('0');
    let mut digits = if digits.is_empty() {
        b"0".to_vec()
    } else {
        digits.as_bytes().to_vec()
    };
    if let Ok(value) = raw.parse::<i64>()
        && let Some(value) = value.checked_add(adjustment)
    {
        return value.to_string();
    }
    // Overflowing exponents have greater magnitude than any adjustment arising
    // from a <=256 KiB mantissa, so their sign cannot change here.
    let increase = negative == (adjustment < 0);
    let mut adjustment = adjustment.unsigned_abs();
    for digit in digits.iter_mut().rev() {
        if adjustment == 0 {
            break;
        }
        let units = (adjustment % 10) as u8;
        adjustment /= 10;
        if increase {
            let value = *digit - b'0' + units;
            *digit = b'0' + value % 10;
            adjustment += u64::from(value >= 10);
        } else {
            let old = *digit - b'0';
            *digit = b'0'
                + if old < units {
                    old + 10 - units
                } else {
                    old - units
                };
            adjustment += u64::from(old < units);
        }
    }
    if adjustment != 0 {
        digits.insert(0, b'0' + adjustment as u8);
    }
    let text = String::from_utf8(digits).expect("decimal digits");
    let text = text.trim_start_matches('0');
    if negative {
        format!("-{}", if text.is_empty() { "0" } else { text })
    } else {
        if text.is_empty() { "0" } else { text }.to_owned()
    }
}
fn number(value: &str) -> (bool, String, String) {
    let negative = value.starts_with('-');
    let unsigned = value.trim_start_matches('-');
    let (mantissa, exponent) = unsigned.split_once(['e', 'E']).unwrap_or((unsigned, "0"));
    let fraction = mantissa.split_once('.').map_or(0, |(_, tail)| tail.len());
    let digits: String = mantissa
        .chars()
        .filter(|character| *character != '.')
        .collect();
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return (false, "0".into(), "0".into());
    }
    let trimmed = digits.trim_end_matches('0');
    let adjustment = (digits.len() - trimmed.len()) as i64 - fraction as i64;
    (
        negative,
        trimmed.to_owned(),
        adjust_exponent(exponent, adjustment),
    )
}
fn equal(left: &Node, right: &Node, arena: &Arena) -> Result<bool, Bypass> {
    Ok(match (left, right) {
        (Node::Null, Node::Null) => true,
        (Node::Bool(a), Node::Bool(b)) => a == b,
        (Node::String(a), Node::String(b)) => a == b,
        (Node::Number(a), Node::Number(b)) => {
            arena.room((a.len() + b.len()).checked_mul(8).ok_or(Bypass::Budget)?)?;
            number(a) == number(b)
        }
        (Node::Array(a), Node::Array(b)) => {
            if a.len() != b.len() {
                return Ok(false);
            }
            for (a, b) in a.iter().zip(b) {
                if !equal(a, b, arena)? {
                    return Ok(false);
                }
            }
            true
        }
        (Node::Object(a), Node::Object(b)) => {
            if a.len() != b.len() {
                return Ok(false);
            }
            for (key, value) in a {
                let Some((_, other)) = b.iter().find(|(candidate, _)| candidate == key) else {
                    return Ok(false);
                };
                if !equal(value, other, arena)? {
                    return Ok(false);
                }
            }
            true
        }
        _ => false,
    })
}

fn write(value: &Node, writer: &mut BudgetedBytes, depth: usize) -> Result<(), Bypass> {
    if depth > DEPTH {
        return Err(Bypass::Budget);
    }
    let bytes = |writer: &mut BudgetedBytes, value: &[u8]| {
        writer.write_all(value).map_err(|_| Bypass::Size)
    };
    match value {
        Node::Null => bytes(writer, b"null")?,
        Node::Bool(true) => bytes(writer, b"true")?,
        Node::Bool(false) => bytes(writer, b"false")?,
        Node::Number(value) => bytes(writer, value.as_bytes())?,
        Node::String(value) => serde_json::to_writer(writer, value).map_err(|_| Bypass::Size)?,
        Node::Array(values) => {
            bytes(writer, b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    bytes(writer, b",")?;
                }
                write(value, writer, depth + 1)?;
            }
            bytes(writer, b"]")?;
        }
        Node::Object(values) => {
            bytes(writer, b"{")?;
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    bytes(writer, b",")?;
                }
                serde_json::to_writer(&mut *writer, key).map_err(|_| Bypass::Size)?;
                bytes(writer, b":")?;
                write(value, writer, depth + 1)?;
            }
            bytes(writer, b"}")?;
        }
    }
    Ok(())
}

pub(super) fn apply(
    input: &str,
    patch: &[PatchOperation],
    budget: &Budget,
) -> Result<BudgetedBytes, Bypass> {
    let _reservation = budget.reserve(ARENA).ok_or(Bypass::Budget)?;
    let mut arena = Arena {
        used: std::mem::size_of::<Node>(),
    };
    let mut root = Parser::parse(input, &mut arena)?;
    for operation in patch {
        let path = match operation {
            PatchOperation::Add { path, .. }
            | PatchOperation::Remove { path }
            | PatchOperation::Replace { path, .. }
            | PatchOperation::Move { path, .. }
            | PatchOperation::Copy { path, .. }
            | PatchOperation::Test { path, .. } => path,
        };
        let path = pointer(path, &mut arena)?;
        match operation {
            PatchOperation::Add { value, .. }
            | PatchOperation::Replace { value, .. }
            | PatchOperation::Test { value, .. } => {
                let mut literal = BudgetedBytes::new(budget, MAX_BODY).ok_or(Bypass::Budget)?;
                serde_json::to_writer(&mut literal, value).map_err(|_| Bypass::Size)?;
                let value = Parser::parse(
                    std::str::from_utf8(literal.as_ref()).map_err(|_| Bypass::Transform)?,
                    &mut arena,
                )?;
                if matches!(operation, PatchOperation::Test { .. }) {
                    if !equal(get(&root, &path)?, &value, &arena)? {
                        return Err(Bypass::Transform);
                    }
                } else if matches!(operation, PatchOperation::Replace { .. }) {
                    *get_mut(&mut root, &path)? = value;
                } else {
                    add(&mut root, &path, value, &mut arena)?;
                }
            }
            PatchOperation::Remove { .. } => {
                remove(&mut root, &path)?;
            }
            PatchOperation::Move { from, .. } | PatchOperation::Copy { from, .. } => {
                let from = pointer(from, &mut arena)?;
                if matches!(operation, PatchOperation::Move { .. }) {
                    if path.starts_with(&from) && path.len() > from.len() {
                        return Err(Bypass::Transform);
                    }
                    if from == path {
                        get(&root, &from)?;
                        continue;
                    }
                    let value = remove(&mut root, &from)?;
                    add(&mut root, &path, value, &mut arena)?;
                } else {
                    let value = duplicate(get(&root, &from)?, &mut arena, 0)?;
                    add(&mut root, &path, value, &mut arena)?;
                }
            }
        }
    }
    if patch
        .iter()
        .all(|operation| matches!(operation, PatchOperation::Test { .. }))
    {
        return BudgetedBytes::copy(budget, input.as_bytes()).ok_or(Bypass::Budget);
    }
    let mut output = BudgetedBytes::new(budget, MAX_BODY).ok_or(Bypass::Budget)?;
    write(&root, &mut output, 0)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn patch(input: &str, operations: serde_json::Value) -> Result<Vec<u8>, Bypass> {
        let patch: Vec<PatchOperation> = serde_json::from_value(operations).unwrap();
        let output = apply(input, &patch, &Budget::default())?;
        Ok(output.as_ref().to_vec())
    }
    #[test]
    fn six_patch_operations_preserve_types_and_pointer_escapes() {
        let output = patch(
            r#"{"a/b":[1,2],"~":true,"n":9007199254740993123456789}"#,
            serde_json::json!([
                {"op":"test","path":"/~0","value":true},
                {"op":"add","path":"/a~1b/-","value":null},
                {"op":"copy","from":"/a~1b/0","path":"/copied"},
                {"op":"move","from":"/a~1b/1","path":"/moved"},
                {"op":"replace","path":"/~0","value":false},
                {"op":"remove","path":"/a~1b/0"}
            ]),
        )
        .unwrap();
        let output = std::str::from_utf8(&output).unwrap();
        assert!(output.contains("9007199254740993123456789"));
        assert!(output.contains(r#""a/b":[null]"#));
        assert!(output.contains(r#""~":false"#));
    }
    #[test]
    fn numeric_test_uses_exact_decimal_equality_and_rejects_duplicate_keys() {
        for text in ["1", "1.0", "1e0", "10e-1"] {
            assert!(patch(text, serde_json::json!([{"op":"test","path":"","value":1}])).is_ok());
        }
        assert!(patch(r#"{"a":1,"\u0061":2}"#, serde_json::json!([])).is_err());
        assert!(patch("[1,2]", serde_json::json!([{"op":"remove","path":"/01"}])).is_err());
        assert!(patch("{}", serde_json::json!([{"op":"remove","path":""}])).is_err());
        assert!(
            patch(
                r#"{"a":{}}"#,
                serde_json::json!([{"op":"move","from":"/a","path":"/a/b"}])
            )
            .is_err()
        );
    }
    #[test]
    fn structural_growth_is_rejected_before_unbounded_cloning() {
        let input = format!("[{}]", "0,".repeat(20_000).trim_end_matches(','));
        assert!(matches!(
            patch(&input, serde_json::json!([])),
            Err(Bypass::Budget)
        ));
        assert_eq!(
            number("10e9999999999999999999999"),
            number("1e10000000000000000000000")
        );
        assert_eq!(
            number("0.0010e-9999999999999999999999"),
            number("1e-10000000000000000000002")
        );
    }
}
