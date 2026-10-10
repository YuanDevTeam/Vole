//! Native, bounded provider transformations; no external interpreter is invoked.
//! Independently designed against the public finite-yq behavior contract.
use super::{Result, VoleError};
use serde_yaml_ng::{Mapping, Number, Value};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const SOURCE_LIMIT: usize = 16 * 1024;
const NODE_LIMIT: usize = 4096;
const COMPILE_NODES: usize = 64 * 1024;
const COMPILE_BYTES: usize = 512 * 1024;
const PARSE_DEPTH: usize = 32;
const VALUE_DEPTH: usize = 64;
const BYTE_LIMIT: usize = 32 * 1024 * 1024;
const STEP_LIMIT: usize = 200_000;
fn error(message: &'static str) -> VoleError {
    VoleError::InvalidConfig(message.into())
}

pub(super) struct Budget<'a> {
    cancel: Option<&'a CancellationToken>,
    started: Instant,
    steps: usize,
    bytes: usize,
    regexes: BTreeMap<String, regex::Regex>,
}
impl<'a> Budget<'a> {
    pub fn new(cancel: Option<&'a CancellationToken>) -> Self {
        Self {
            cancel,
            started: Instant::now(),
            steps: 0,
            bytes: 0,
            regexes: BTreeMap::new(),
        }
    }
    fn tick(&mut self, amount: usize) -> Result<()> {
        if self.cancel.is_some_and(CancellationToken::is_cancelled) {
            return Err(error("provider override expression cancelled"));
        }
        self.steps = self
            .steps
            .checked_add(amount)
            .ok_or_else(|| error("provider override execution budget exceeded"))?;
        if self.steps > STEP_LIMIT || self.started.elapsed() > Duration::from_millis(100) {
            return Err(error("provider override execution budget exceeded"));
        }
        Ok(())
    }
    fn reserve(&mut self, bytes: usize) -> Result<()> {
        self.tick(1)?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| error("provider override output budget exceeded"))?;
        if self.bytes > BYTE_LIMIT {
            return Err(error("provider override output budget exceeded"));
        }
        Ok(())
    }
    fn clone_value(&mut self, value: &Value) -> Result<Value> {
        let bytes = self.measure(value, 0)?;
        self.reserve(bytes)?;
        Ok(value.clone())
    }
    fn measure(&mut self, value: &Value, depth: usize) -> Result<usize> {
        self.tick(1)?;
        if depth > VALUE_DEPTH {
            return Err(error("provider override value depth exceeded"));
        }
        let mut bytes = std::mem::size_of::<Value>();
        match value {
            Value::String(text) => bytes = bytes.saturating_add(text.len()),
            Value::Sequence(values) => {
                for value in values {
                    bytes = bytes.saturating_add(self.measure(value, depth + 1)?);
                }
            }
            Value::Mapping(map) => {
                for (key, value) in map {
                    bytes = bytes
                        .saturating_add(self.measure(key, depth + 1)?)
                        .saturating_add(self.measure(value, depth + 1)?);
                }
            }
            Value::Tagged(_) => return Err(error("provider override does not support YAML tags")),
            _ => {}
        }
        if bytes > BYTE_LIMIT {
            return Err(error("provider override output budget exceeded"));
        }
        Ok(bytes)
    }
    fn regex(&mut self, pattern: &str) -> Result<regex::Regex> {
        self.tick(1)?;
        if pattern.len() > 4096 {
            return Err(error("provider override regex compilation budget exceeded"));
        }
        if let Some(regex) = self.regexes.get(pattern) {
            return Ok(regex.clone());
        }
        if self.regexes.len() >= 32 {
            return Err(error("provider override regex compilation budget exceeded"));
        }
        self.reserve(pattern.len().saturating_add(512 * 1024))?;
        let regex = compile_regex(pattern)?;
        self.regexes.insert(pattern.into(), regex.clone());
        Ok(regex)
    }
}

fn compile_regex(pattern: &str) -> Result<regex::Regex> {
    if pattern.len() > 4096 {
        return Err(error("provider override regex compilation budget exceeded"));
    }
    // RE2's Perl shorthand classes are ASCII. Keep Unicode literal/range matching
    // while expanding those classes before using Rust's bounded linear engine.
    let mut adapted = String::new();
    let mut characters = pattern.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            adapted.push(character);
            continue;
        }
        match characters.next() {
            Some('d') => adapted.push_str("[0-9]"),
            Some('D') => adapted.push_str("[^0-9]"),
            Some('w') => adapted.push_str("[A-Za-z0-9_]"),
            Some('W') => adapted.push_str("[^A-Za-z0-9_]"),
            Some('s') => adapted.push_str(r"[\t\n\f\r ]"),
            Some('S') => adapted.push_str(r"[^\t\n\f\r ]"),
            Some('b') => adapted.push_str(r"(?-u:\b)"),
            Some('B') => adapted.push_str(r"(?-u:\B)"),
            Some('Q') => {
                let mut quoted = String::new();
                while let Some(character) = characters.next() {
                    if character == '\\' && characters.peek() == Some(&'E') {
                        characters.next();
                        break;
                    }
                    quoted.push(character);
                }
                adapted.push_str(&regex::escape(&quoted));
            }
            Some(character) => {
                adapted.push('\\');
                adapted.push(character);
            }
            None => adapted.push('\\'),
        }
    }
    regex::RegexBuilder::new(&adapted)
        .octal(true)
        .size_limit(512 * 1024)
        .dfa_size_limit(512 * 1024)
        .build()
        .map_err(|_| error("invalid provider override regular expression"))
}

#[derive(Clone)]
pub(super) struct Expr {
    root: Node,
    regexes: BTreeMap<String, regex::Regex>,
}
impl PartialEq for Expr {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}
impl Eq for Expr {}
impl std::fmt::Debug for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderExpr").finish_non_exhaustive()
    }
}
impl Expr {
    #[cfg(test)]
    pub fn parse(source: &str) -> Result<Self> {
        Self::parse_with_budget(source, &mut CompileBudget::default())
    }
    pub fn parse_with_budget(source: &str, limits: &mut CompileBudget) -> Result<Self> {
        limits.check()?;
        let initial_nodes = limits.nodes;
        let initial_tokens = limits.tokens;
        let root = parse(source, limits, 0)?;
        if limits.nodes.saturating_sub(initial_nodes) > NODE_LIMIT
            || limits.tokens.saturating_sub(initial_tokens) > NODE_LIMIT
        {
            return Err(error("provider override compilation budget exceeded"));
        }
        validate(&root, 0)?;
        let mut regexes = BTreeMap::new();
        compile_literal_regexes(&root, &mut regexes, limits)?;
        Ok(Self { root, regexes })
    }
    pub fn apply(&self, mapping: &mut Value, budget: &mut Budget<'_>) -> Result<()> {
        if !mapping.is_mapping() {
            return Err(error("provider override input must be a mapping"));
        }
        for (pattern, regex) in &self.regexes {
            budget.tick(1)?;
            if !budget.regexes.contains_key(pattern) {
                if budget.regexes.len() >= 32 {
                    return Err(error("provider override regex compilation budget exceeded"));
                }
                budget.reserve(pattern.len().saturating_add(512 * 1024))?;
                budget.regexes.insert(pattern.clone(), regex.clone());
            }
        }
        let input = budget.clone_value(mapping)?;
        let mut result = evaluate(&self.root, vec![input], budget, 0)?;
        if result.len() != 1 || !result[0].is_mapping() {
            return Err(error("provider override must produce exactly one mapping"));
        }
        budget.measure(&result[0], 0)?;
        *mapping = result.pop().expect("one result");
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq)]
enum Segment {
    Key(String),
    Index(i64),
    Each,
}
#[derive(Clone, PartialEq, Eq)]
enum Part {
    Text(String),
    Expression(Node),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Default,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Update {
    Assign,
    Replace,
    Add,
    Sub,
    Mul,
}
#[derive(Clone, PartialEq, Eq)]
enum Node {
    Literal(Value),
    Path(Vec<Segment>),
    String(Vec<Part>),
    Array(Box<Node>),
    Object(Vec<(String, Node)>),
    Binary(Op, Box<Node>, Box<Node>),
    Neg(Box<Node>),
    Pipe(Box<Node>, Box<Node>),
    Union(Box<Node>, Box<Node>),
    Call(String, Vec<Node>),
    Update(Update, Box<Node>, Box<Node>),
    Delete(Vec<Node>),
    Group(Box<Node>),
}
#[derive(Clone, PartialEq, Eq)]
enum Token {
    Dot,
    Word(String),
    String(String),
    Number(String),
    Symbol(&'static str),
    End,
}
pub(super) struct CompileBudget {
    tokens: usize,
    nodes: usize,
    bytes: usize,
    started: Instant,
    regexes: BTreeMap<String, regex::Regex>,
}
impl Default for CompileBudget {
    fn default() -> Self {
        Self {
            tokens: 0,
            nodes: 0,
            bytes: 0,
            started: Instant::now(),
            regexes: BTreeMap::new(),
        }
    }
}
impl CompileBudget {
    fn check(&self) -> Result<()> {
        if self.started.elapsed() > Duration::from_secs(1)
            || self.tokens > COMPILE_NODES
            || self.nodes > COMPILE_NODES
        {
            return Err(error("provider override compilation budget exceeded"));
        }
        Ok(())
    }
}
fn lex(source: &str, limits: &mut CompileBudget) -> Result<Vec<Token>> {
    limits.bytes = limits.bytes.saturating_add(source.len());
    limits.check()?;
    if source.len() > SOURCE_LIMIT || limits.bytes > COMPILE_BYTES {
        return Err(error("provider override compilation budget exceeded"));
    }
    let bytes = source.as_bytes();
    let mut cursor = 0;
    let mut tokens = Vec::new();
    while cursor < bytes.len() {
        let start = cursor;
        let ch = source[cursor..].chars().next().expect("valid character");
        if ch.is_whitespace() {
            cursor += ch.len_utf8();
            continue;
        }
        if ch == '#' {
            break;
        }
        let token = if ch == '"' {
            cursor += 1;
            let content = cursor;
            let mut escaped = false;
            while cursor < bytes.len() {
                let byte = bytes[cursor];
                if !escaped && byte == b'"' {
                    break;
                }
                escaped = !escaped && byte == b'\\';
                cursor += 1;
            }
            if cursor == bytes.len() {
                return Err(error("invalid provider override string"));
            }
            let text = source[content..cursor].to_owned();
            cursor += 1;
            Token::String(text)
        } else if ch.is_ascii_digit() {
            cursor += 1;
            while cursor < bytes.len() {
                let byte = bytes[cursor];
                if byte.is_ascii_alphanumeric()
                    || byte == b'.'
                    || ((byte == b'+' || byte == b'-') && matches!(bytes[cursor - 1], b'e' | b'E'))
                {
                    cursor += 1;
                } else {
                    break;
                }
            }
            Token::Number(source[start..cursor].into())
        } else if ch.is_alphabetic() || ch == '_' {
            cursor += ch.len_utf8();
            while cursor < bytes.len() {
                let ch = source[cursor..].chars().next().expect("valid character");
                if ch.is_alphanumeric() || matches!(ch, '_' | '-') {
                    cursor += ch.len_utf8();
                } else {
                    break;
                }
            }
            Token::Word(source[start..cursor].into())
        } else {
            let mut matched = None;
            for symbol in [
                "|=", "+=", "-=", "*=", "//", "==", "!=", "<=", ">=", "(", ")", "[", "]", "{", "}",
                ",", ";", ":", "|", "=", "+", "-", "*", "/", "%", "<", ">", "~",
            ] {
                if source[cursor..].starts_with(symbol) {
                    matched = Some(symbol);
                    break;
                }
            }
            if ch == '.' {
                cursor += 1;
                Token::Dot
            } else if let Some(symbol) = matched {
                cursor += symbol.len();
                Token::Symbol(symbol)
            } else {
                return Err(error("unsupported provider override syntax"));
            }
        };
        limits.tokens += 1;
        limits.check()?;
        if tokens.len() >= NODE_LIMIT {
            return Err(error("provider override compilation budget exceeded"));
        }
        tokens.push(token);
    }
    tokens.push(Token::End);
    Ok(tokens)
}
struct Parser<'a> {
    tokens: Vec<Token>,
    cursor: usize,
    limits: &'a mut CompileBudget,
}
fn parse(source: &str, limits: &mut CompileBudget, depth: usize) -> Result<Node> {
    if depth > PARSE_DEPTH {
        return Err(error("provider override expression depth exceeded"));
    }
    let tokens = lex(source, limits)?;
    if tokens.len() == 1 {
        limits.nodes += 1;
        limits.check()?;
        return Ok(Node::Path(Vec::new()));
    }
    let mut parser = Parser {
        tokens,
        cursor: 0,
        limits,
    };
    let node = parser.expression(0, depth + 1)?;
    if parser.peek() != &Token::End {
        return Err(error("invalid provider override expression"));
    }
    Ok(node)
}
impl Parser<'_> {
    fn peek(&self) -> &Token {
        &self.tokens[self.cursor]
    }
    fn next(&mut self) -> Token {
        let result = self.tokens[self.cursor].clone();
        self.cursor += 1;
        result
    }
    fn symbol(&mut self, symbol: &'static str) -> bool {
        if self.peek() == &Token::Symbol(symbol) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, symbol: &'static str) -> Result<()> {
        if self.symbol(symbol) {
            Ok(())
        } else {
            Err(error("invalid provider override expression"))
        }
    }
    fn account(&mut self, node: Node) -> Result<Node> {
        self.limits.nodes += 1;
        if self.limits.nodes > COMPILE_NODES {
            return Err(error("provider override compilation budget exceeded"));
        }
        Ok(node)
    }
    fn expression(&mut self, minimum: u8, depth: usize) -> Result<Node> {
        if depth > PARSE_DEPTH {
            return Err(error("provider override expression depth exceeded"));
        }
        let mut node = self.primary(depth + 1)?;
        loop {
            let (precedence, kind) = match self.peek() {
                Token::Symbol(",") => (1, 0),
                Token::Symbol("|") => (2, 1),
                Token::Symbol("=" | "|=" | "+=" | "-=" | "*=") => (3, 2),
                Token::Word(word) if word == "or" => (4, 3),
                Token::Word(word) if word == "and" => (5, 3),
                Token::Symbol("//") => (6, 3),
                Token::Symbol("==" | "!=" | "<" | "<=" | ">" | ">=") => (7, 3),
                Token::Symbol("+" | "-") => (8, 3),
                Token::Symbol("*" | "/" | "%") => (9, 3),
                _ => break,
            };
            if precedence < minimum {
                break;
            }
            if matches!(node, Node::Update(..))
                && matches!(self.peek(), Token::Word(word) if word == "and" || word == "or")
            {
                return Err(error(
                    "provider override boolean assignment values require parentheses",
                ));
            }
            let operator = self.next();
            let right = self.expression(if kind == 2 { 6 } else { precedence + 1 }, depth + 1)?;
            node = self.account(match kind {
                0 => Node::Union(Box::new(node), Box::new(right)),
                1 => Node::Pipe(Box::new(node), Box::new(right)),
                2 => Node::Update(
                    match operator {
                        Token::Symbol("=") => Update::Assign,
                        Token::Symbol("|=") => Update::Replace,
                        Token::Symbol("+=") => Update::Add,
                        Token::Symbol("-=") => Update::Sub,
                        _ => Update::Mul,
                    },
                    Box::new(node),
                    Box::new(right),
                ),
                _ => Node::Binary(
                    match operator {
                        Token::Word(word) if word == "and" => Op::And,
                        Token::Word(_) => Op::Or,
                        Token::Symbol("//") => Op::Default,
                        Token::Symbol("+") => Op::Add,
                        Token::Symbol("-") => Op::Sub,
                        Token::Symbol("*") => Op::Mul,
                        Token::Symbol("/") => Op::Div,
                        Token::Symbol("%") => Op::Mod,
                        Token::Symbol("==") => Op::Eq,
                        Token::Symbol("!=") => Op::Ne,
                        Token::Symbol("<") => Op::Lt,
                        Token::Symbol("<=") => Op::Le,
                        Token::Symbol(">") => Op::Gt,
                        _ => Op::Ge,
                    },
                    Box::new(node),
                    Box::new(right),
                ),
            })?;
        }
        Ok(node)
    }
    fn primary(&mut self, depth: usize) -> Result<Node> {
        let node = match self.next() {
            Token::Dot => {
                let mut segments = Vec::new();
                if matches!(self.peek(), Token::Word(_) | Token::String(_)) {
                    segments.push(self.field()?);
                }
                loop {
                    if self.peek() == &Token::Dot {
                        self.next();
                        segments.push(self.field()?);
                    } else if self.symbol("[") {
                        if self.symbol("]") {
                            segments.push(Segment::Each);
                            continue;
                        }
                        let segment = match self.next() {
                            Token::String(raw) => Segment::Key(decode_string(&raw)?),
                            Token::Number(number) => Segment::Index(
                                number
                                    .parse()
                                    .map_err(|_| error("invalid provider override index"))?,
                            ),
                            Token::Symbol("-") => match self.next() {
                                Token::Number(number) => Segment::Index(
                                    number
                                        .parse::<i64>()
                                        .ok()
                                        .and_then(i64::checked_neg)
                                        .ok_or_else(|| error("invalid provider override index"))?,
                                ),
                                _ => return Err(error("invalid provider override index")),
                            },
                            _ => return Err(error("unsupported provider override path")),
                        };
                        self.expect("]")?;
                        segments.push(segment);
                    } else {
                        break;
                    }
                }
                if segments.len() > PARSE_DEPTH {
                    return Err(error("provider override path depth exceeded"));
                }
                Node::Path(segments)
            }
            Token::Number(number) => Node::Literal(number_value(&number, false)?),
            Token::String(raw) => Node::String(interpolation(&raw, self.limits, depth + 1)?),
            Token::Symbol("~") => Node::Literal(Value::Null),
            Token::Symbol("-") => Node::Neg(Box::new(self.expression(10, depth + 1)?)),
            Token::Symbol("(") => {
                let node = self.expression(0, depth + 1)?;
                self.expect(")")?;
                Node::Group(Box::new(node))
            }
            Token::Symbol("[") => {
                if self.symbol("]") {
                    Node::Literal(Value::Sequence(Vec::new()))
                } else {
                    let node = self.expression(0, depth + 1)?;
                    self.expect("]")?;
                    Node::Array(Box::new(node))
                }
            }
            Token::Symbol("{") => {
                let mut entries = Vec::new();
                if !self.symbol("}") {
                    loop {
                        let Token::String(raw) = self.next() else {
                            return Err(error(
                                "provider override mapping keys must be quoted strings",
                            ));
                        };
                        let key = decode_string(&raw)?;
                        self.expect(":")?;
                        entries.push((key, self.expression(2, depth + 1)?));
                        if self.symbol("}") {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                Node::Object(entries)
            }
            Token::Word(name) => match name.as_str() {
                "null" => Node::Literal(Value::Null),
                "true" => Node::Literal(Value::Bool(true)),
                "false" => Node::Literal(Value::Bool(false)),
                _ => {
                    if ![
                        "length",
                        "keys",
                        "has",
                        "contains",
                        "select",
                        "reverse",
                        "sort",
                        "unique",
                        "flatten",
                        "any",
                        "all",
                        "map",
                        "map_values",
                        "filter",
                        "to_entries",
                        "from_entries",
                        "with_entries",
                        "any_c",
                        "all_c",
                        "test",
                        "sub",
                        "split",
                        "join",
                        "upcase",
                        "downcase",
                        "trim",
                        "tostring",
                        "tonumber",
                        "type",
                        "not",
                        "del",
                    ]
                    .contains(&name.as_str())
                    {
                        return Err(error("unsupported provider override function"));
                    }
                    let mut arguments = Vec::new();
                    if self.symbol("(") && !self.symbol(")") {
                        loop {
                            let collecting = [
                                "map",
                                "map_values",
                                "filter",
                                "with_entries",
                                "any_c",
                                "all_c",
                            ]
                            .contains(&name.as_str());
                            arguments
                                .push(self.expression(if collecting { 0 } else { 2 }, depth + 1)?);
                            if self.symbol(")") {
                                break;
                            }
                            if !self.symbol(",") {
                                self.expect(";")?;
                            }
                        }
                    }
                    if name == "del" {
                        Node::Delete(arguments)
                    } else {
                        Node::Call(name, arguments)
                    }
                }
            },
            _ => return Err(error("invalid provider override value")),
        };
        self.account(node)
    }
    fn field(&mut self) -> Result<Segment> {
        match self.next() {
            Token::Word(name) => Ok(Segment::Key(name)),
            Token::String(raw) => Ok(Segment::Key(decode_string(&raw)?)),
            _ => Err(error("invalid provider override field")),
        }
    }
}
fn decode_string(raw: &str) -> Result<String> {
    let mut output = String::new();
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => output.push('\n'),
                Some('"') => output.push('"'),
                Some('\\') => output.push('\\'),
                Some(other) => {
                    output.push('\\');
                    output.push(other);
                }
                None => return Err(error("invalid provider override string")),
            }
        } else {
            output.push(ch);
        }
    }
    Ok(output)
}
fn interpolation(raw: &str, limits: &mut CompileBudget, depth: usize) -> Result<Vec<Part>> {
    let mut parts = Vec::new();
    let mut plain = String::new();
    let mut cursor = 0;
    while cursor < raw.len() {
        if raw[cursor..].starts_with("\\\\") {
            plain.push_str("\\\\");
            cursor += 2;
            continue;
        }
        if raw[cursor..].starts_with("\\(") {
            if !plain.is_empty() {
                parts.push(Part::Text(decode_string(&plain)?));
                plain.clear();
            }
            cursor += 2;
            let start = cursor;
            let mut nested = 1;
            let mut quoted = false;
            let mut escaped = false;
            while cursor < raw.len() {
                let byte = raw.as_bytes()[cursor];
                if !escaped && byte == b'"' {
                    quoted = !quoted;
                }
                if !quoted && !escaped {
                    if byte == b'(' {
                        nested += 1;
                    } else if byte == b')' {
                        nested -= 1;
                        if nested == 0 {
                            break;
                        }
                    }
                }
                escaped = !escaped && byte == b'\\';
                cursor += 1;
            }
            if nested != 0 {
                return Err(error("invalid provider override interpolation"));
            }
            let expression = raw[start..cursor].replace("\\\"", "\"");
            parts.push(Part::Expression(parse(&expression, limits, depth + 1)?));
            cursor += 1;
        } else {
            let ch = raw[cursor..].chars().next().expect("valid character");
            plain.push(ch);
            cursor += ch.len_utf8();
        }
    }
    if !plain.is_empty() {
        parts.push(Part::Text(decode_string(&plain)?));
    }
    Ok(parts)
}
fn number_value(text: &str, conversion: bool) -> Result<Value> {
    let integer = if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
    {
        i64::from_str_radix(digits, 16).ok()
    } else if conversion && let Some(digits) = text.strip_prefix("0o") {
        i64::from_str_radix(digits, 8).ok()
    } else {
        text.parse::<i64>().ok()
    };
    if let Some(integer) = integer {
        return Ok(Value::Number(integer.into()));
    }
    if !conversion && !text.contains(['.', 'e', 'E']) {
        return Err(error("invalid provider override integer"));
    }
    if text.starts_with("0b")
        || text.starts_with("0B")
        || text.starts_with("0o")
        || text.starts_with("0O")
        || text.starts_with("0x")
        || text.starts_with("0X")
    {
        return Err(error("invalid provider override number"));
    }
    let number = text
        .parse::<f64>()
        .map_err(|_| error("invalid provider override number"))?;
    if !number.is_finite()
        && !(conversion
            && matches!(
                text,
                "NaN"
                    | "nan"
                    | "Inf"
                    | "inf"
                    | "+Inf"
                    | "+inf"
                    | "-Inf"
                    | "-inf"
                    | "Infinity"
                    | "infinity"
                    | "+Infinity"
                    | "+infinity"
                    | "-Infinity"
                    | "-infinity"
            ))
    {
        return Err(error("provider override number overflow"));
    }
    Ok(Value::Number(Number::from(number)))
}

fn validate(node: &Node, depth: usize) -> Result<()> {
    if depth > PARSE_DEPTH {
        return Err(error("provider override expression depth exceeded"));
    }
    match node {
        Node::Update(_, target, value) => {
            validate_target(target)?;
            validate(target, depth + 1)?;
            validate(value, depth + 1)?;
        }
        Node::Delete(paths) => {
            if paths.is_empty() {
                return Err(error("invalid provider override deletion"));
            }
            for path in paths {
                validate_target(path)?;
                if matches!(path, Node::Path(path) if path.is_empty()) {
                    return Err(error("provider override cannot delete the root"));
                }
                validate(path, depth + 1)?;
            }
        }
        Node::Call(name, arguments) => {
            let expected = match name.as_str() {
                "has" | "contains" | "select" | "split" | "join" => 1..=1,
                "map" | "map_values" | "filter" | "with_entries" | "any_c" | "all_c" => {
                    1..=usize::MAX
                }
                "sub" => 2..=2,
                "test" => 1..=2,
                "flatten" => 0..=1,
                _ => 0..=0,
            };
            if !expected.contains(&arguments.len()) {
                return Err(error("invalid provider override function arguments"));
            }
            for argument in arguments {
                validate(argument, depth + 1)?;
            }
        }
        Node::Pipe(a, b) | Node::Union(a, b) | Node::Binary(_, a, b) => {
            validate(a, depth + 1)?;
            validate(b, depth + 1)?;
        }
        Node::Array(node) | Node::Neg(node) | Node::Group(node) => validate(node, depth + 1)?,
        Node::Object(entries) => {
            for (_, node) in entries {
                validate(node, depth + 1)?;
            }
        }
        Node::String(parts) => {
            for part in parts {
                if let Part::Expression(node) = part {
                    validate(node, depth + 1)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
fn validate_target(node: &Node) -> Result<()> {
    match node {
        Node::Path(_) => Ok(()),
        Node::Group(node) => validate_target(node),
        Node::Pipe(a, b) | Node::Union(a, b) => {
            validate_target(a)?;
            validate_target(b)
        }
        Node::Call(name, arguments) if name == "select" && arguments.len() == 1 => Ok(()),
        _ => Err(error("invalid provider override update target")),
    }
}
fn compile_literal_regexes(
    node: &Node,
    output: &mut BTreeMap<String, regex::Regex>,
    limits: &mut CompileBudget,
) -> Result<()> {
    limits.check()?;
    match node {
        Node::Call(name, arguments) => {
            if matches!(name.as_str(), "test" | "sub")
                && let Some(Node::String(parts)) = arguments.first()
                && parts.iter().all(|part| matches!(part, Part::Text(_)))
            {
                let pattern = parts
                    .iter()
                    .filter_map(|part| {
                        if let Part::Text(text) = part {
                            Some(text.as_str())
                        } else {
                            None
                        }
                    })
                    .collect::<String>();
                if pattern.len() > 4096 || output.len() >= 32 {
                    return Err(error("provider override regex compilation budget exceeded"));
                }
                let regex = if let Some(regex) = limits.regexes.get(&pattern) {
                    regex.clone()
                } else {
                    if limits.regexes.len() >= 32 {
                        return Err(error("provider override regex compilation budget exceeded"));
                    }
                    let regex = compile_regex(&pattern)?;
                    limits.regexes.insert(pattern.clone(), regex.clone());
                    regex
                };
                output.insert(pattern, regex);
            }
            for node in arguments {
                compile_literal_regexes(node, output, limits)?;
            }
        }
        Node::Pipe(a, b) | Node::Union(a, b) | Node::Binary(_, a, b) | Node::Update(_, a, b) => {
            compile_literal_regexes(a, output, limits)?;
            compile_literal_regexes(b, output, limits)?;
        }
        Node::Array(node) | Node::Neg(node) | Node::Group(node) => {
            compile_literal_regexes(node, output, limits)?
        }
        Node::Delete(nodes) => {
            for node in nodes {
                compile_literal_regexes(node, output, limits)?;
            }
        }
        Node::Object(entries) => {
            for (_, node) in entries {
                compile_literal_regexes(node, output, limits)?;
            }
        }
        Node::String(parts) => {
            for part in parts {
                if let Part::Expression(node) = part {
                    compile_literal_regexes(node, output, limits)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn evaluate(
    node: &Node,
    inputs: Vec<Value>,
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<Vec<Value>> {
    budget.tick(1)?;
    if depth > PARSE_DEPTH {
        return Err(error("provider override evaluation depth exceeded"));
    }
    match node {
        Node::Pipe(left, right) => {
            let values = evaluate(left, inputs, budget, depth + 1)?;
            evaluate(right, values, budget, depth + 1)
        }
        Node::Union(left, right) => {
            let copies = inputs
                .iter()
                .map(|value| budget.clone_value(value))
                .collect::<Result<Vec<_>>>()?;
            let mut values = evaluate(left, copies, budget, depth + 1)?;
            let other = evaluate(right, inputs, budget, depth + 1)?;
            budget.reserve(other.len().saturating_mul(std::mem::size_of::<Value>()))?;
            values.extend(other);
            Ok(values)
        }
        Node::Group(node) => evaluate(node, inputs, budget, depth + 1),
        _ => {
            let mut output = Vec::new();
            for input in inputs {
                budget.tick(1)?;
                let values = single(node, &input, budget, depth + 1)?;
                budget.reserve(values.len().saturating_mul(std::mem::size_of::<Value>()))?;
                output.extend(values);
            }
            Ok(output)
        }
    }
}
fn one(node: &Node, input: &Value, budget: &mut Budget<'_>, depth: usize) -> Result<Option<Value>> {
    let input = budget.clone_value(input)?;
    let mut values = evaluate(node, vec![input], budget, depth + 1)?;
    if values.len() > 1 {
        return Err(error(
            "provider override value must collect multiple results",
        ));
    }
    Ok(values.pop())
}
fn single(node: &Node, input: &Value, budget: &mut Budget<'_>, depth: usize) -> Result<Vec<Value>> {
    budget.tick(1)?;
    match node {
        Node::Literal(value) => Ok(vec![budget.clone_value(value)?]),
        Node::Path(path) => lookup(input, path, budget, 0),
        Node::String(parts) => {
            let mut output = String::new();
            for part in parts {
                let text = match part {
                    Part::Text(text) => {
                        budget.reserve(text.len())?;
                        text.clone()
                    }
                    Part::Expression(node) => {
                        let input = budget.clone_value(input)?;
                        let result = evaluate(node, vec![input], budget, depth + 1)?;
                        result
                            .first()
                            .map(|value| text(value, budget))
                            .transpose()?
                            .unwrap_or_default()
                    }
                };
                append(&mut output, &text, budget)?;
            }
            Ok(vec![Value::String(output)])
        }
        Node::Array(node) => {
            let input = budget.clone_value(input)?;
            let values = evaluate(node, vec![input], budget, depth + 1)?;
            Ok(vec![Value::Sequence(values)])
        }
        Node::Object(entries) => {
            let mut map = Mapping::new();
            for (key, node) in entries {
                let copy = budget.clone_value(input)?;
                let mut values = evaluate(node, vec![copy], budget, depth + 1)?;
                if let Some(value) = values.pop() {
                    budget.reserve(key.len() + std::mem::size_of::<Value>() * 2)?;
                    map.insert(Value::String(key.clone()), value);
                }
            }
            Ok(vec![Value::Mapping(map)])
        }
        Node::Neg(node) => {
            let Some(value) = one(node, input, budget, depth)? else {
                return Ok(vec![]);
            };
            if let Some(integer) = value.as_i64() {
                Ok(vec![Value::Number(integer.wrapping_neg().into())])
            } else {
                Ok(vec![Value::Number(Number::from(-numeric(&value)?))])
            }
        }
        Node::Binary(operator, left, right) => {
            let copy = budget.clone_value(input)?;
            let left = evaluate(left, vec![copy], budget, depth + 1)?;
            if *operator == Op::Default {
                let mut output = Vec::new();
                if left.is_empty() {
                    let copy = budget.clone_value(input)?;
                    return evaluate(right, vec![copy], budget, depth + 1);
                }
                for value in left {
                    if truthy(&value) {
                        output.push(value);
                    } else {
                        let copy = budget.clone_value(input)?;
                        output.extend(evaluate(right, vec![copy], budget, depth + 1)?);
                    }
                }
                return Ok(output);
            }
            let copy = budget.clone_value(input)?;
            let right = evaluate(right, vec![copy], budget, depth + 1)?;
            let count = left
                .len()
                .checked_mul(right.len())
                .ok_or_else(|| error("provider override output budget exceeded"))?;
            budget.reserve(count.saturating_mul(std::mem::size_of::<Value>()))?;
            let mut output = Vec::with_capacity(count);
            for a in &left {
                for b in &right {
                    output.push(binary(*operator, a, b, budget, 0)?);
                }
            }
            Ok(output)
        }
        Node::Call(name, arguments) => call(name, arguments, input, budget, depth),
        Node::Update(operation, target, value) => {
            let paths = select_paths(target, input, vec![vec![]], budget, depth + 1)?;
            let mut output = budget.clone_value(input)?;
            for path in paths {
                let old = get_path(input, &path).unwrap_or(&Value::Null);
                let context = if *operation == Update::Replace {
                    old
                } else {
                    input
                };
                let Some(right) = one(value, context, budget, depth)? else {
                    continue;
                };
                let replacement = match operation {
                    Update::Assign | Update::Replace => right,
                    Update::Add => binary(Op::Add, old, &right, budget, 0)?,
                    Update::Sub => binary(Op::Sub, old, &right, budget, 0)?,
                    Update::Mul => binary(Op::Mul, old, &right, budget, 0)?,
                };
                set_path(&mut output, &path, replacement, budget, 0)?;
            }
            Ok(vec![output])
        }
        Node::Delete(targets) => {
            let mut paths = Vec::new();
            for target in targets {
                paths.extend(select_paths(
                    target,
                    input,
                    vec![vec![]],
                    budget,
                    depth + 1,
                )?);
            }
            if paths.iter().any(Vec::is_empty) {
                return Err(error("provider override cannot delete the root"));
            }
            // Long paths first; equal-depth array indexes descend, preserving original selectors.
            paths.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
            paths.dedup();
            let mut output = budget.clone_value(input)?;
            for path in paths {
                delete_path(&mut output, &path, budget)?;
            }
            Ok(vec![output])
        }
        Node::Pipe(_, _) | Node::Union(_, _) | Node::Group(_) => {
            let input = budget.clone_value(input)?;
            evaluate(node, vec![input], budget, depth + 1)
        }
    }
}
fn append(output: &mut String, text: &str, budget: &mut Budget<'_>) -> Result<()> {
    budget.reserve(text.len())?;
    output.push_str(text);
    Ok(())
}
fn lookup(
    value: &Value,
    path: &[Segment],
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<Vec<Value>> {
    budget.tick(1)?;
    if depth > VALUE_DEPTH {
        return Err(error("provider override value depth exceeded"));
    }
    let Some((segment, rest)) = path.split_first() else {
        return Ok(vec![budget.clone_value(value)?]);
    };
    match segment {
        Segment::Key(key) => lookup(
            value
                .as_mapping()
                .and_then(|map| map.get(key.as_str()))
                .unwrap_or(&Value::Null),
            rest,
            budget,
            depth + 1,
        ),
        Segment::Index(index) => lookup(
            value
                .as_sequence()
                .and_then(|array| {
                    normalized_index(*index, array.len()).and_then(|index| array.get(index))
                })
                .unwrap_or(&Value::Null),
            rest,
            budget,
            depth + 1,
        ),
        Segment::Each => {
            let mut output = Vec::new();
            if !value.is_sequence() && !value.is_mapping() {
                return Ok(output);
            }
            for (_, value) in members(value, budget)? {
                output.extend(lookup(value, rest, budget, depth + 1)?);
            }
            Ok(output)
        }
    }
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Field(String),
    Index(usize),
}
fn normalized_index(index: i64, length: usize) -> Option<usize> {
    if index < 0 {
        usize::try_from(i64::try_from(length).ok()?.checked_add(index)?).ok()
    } else {
        usize::try_from(index).ok()
    }
}
fn members<'a>(value: &'a Value, budget: &mut Budget<'_>) -> Result<Vec<(Key, &'a Value)>> {
    let length = match value {
        Value::Sequence(values) => values.len(),
        Value::Mapping(values) => values.len(),
        _ => 0,
    };
    budget.tick(length.saturating_mul(1 + length.checked_ilog2().unwrap_or(0) as usize))?;
    budget.reserve(length.saturating_mul(std::mem::size_of::<(Key, &Value)>()))?;
    if let Value::Mapping(map) = value {
        for key in map.keys() {
            if let Some(key) = key.as_str() {
                budget.reserve(key.len())?;
            }
        }
    }
    match value {
        Value::Sequence(values) => Ok(values
            .iter()
            .enumerate()
            .map(|(index, value)| (Key::Index(index), value))
            .collect()),
        Value::Mapping(map) => {
            let mut values = map
                .iter()
                .map(|(key, value)| {
                    key.as_str()
                        .map(|key| (Key::Field(key.into()), value))
                        .ok_or_else(|| error("provider override requires string mapping keys"))
                })
                .collect::<Result<Vec<_>>>()?;
            values.sort_by(|(a, _), (b, _)| a.cmp(b));
            Ok(values)
        }
        _ => Err(error(
            "provider override collection function requires an array or mapping",
        )),
    }
}
fn get_path<'a>(value: &'a Value, path: &[Key]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = match key {
            Key::Field(key) => current.as_mapping()?.get(key.as_str())?,
            Key::Index(index) => current.as_sequence()?.get(*index)?,
        };
    }
    Some(current)
}
fn select_paths(
    node: &Node,
    root: &Value,
    inputs: Vec<Vec<Key>>,
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<Vec<Vec<Key>>> {
    budget.tick(1)?;
    if depth > PARSE_DEPTH {
        return Err(error("provider override target depth exceeded"));
    }
    match node {
        Node::Group(node) => select_paths(node, root, inputs, budget, depth + 1),
        Node::Pipe(left, right) => {
            let inputs = select_paths(left, root, inputs, budget, depth + 1)?;
            select_paths(right, root, inputs, budget, depth + 1)
        }
        Node::Union(left, right) => {
            budget.reserve(
                inputs
                    .iter()
                    .map(|path| {
                        path.len() * std::mem::size_of::<Key>()
                            + path
                                .iter()
                                .map(|key| match key {
                                    Key::Field(key) => key.len(),
                                    Key::Index(_) => 0,
                                })
                                .sum::<usize>()
                    })
                    .sum(),
            )?;
            let mut output = select_paths(left, root, inputs.clone(), budget, depth + 1)?;
            output.extend(select_paths(right, root, inputs, budget, depth + 1)?);
            Ok(output)
        }
        Node::Call(name, args) if name == "select" => {
            let mut output = Vec::new();
            for path in inputs {
                if let Some(value) = one(
                    &args[0],
                    get_path(root, &path).unwrap_or(&Value::Null),
                    budget,
                    depth,
                )? && truthy(&value)
                {
                    output.push(path);
                }
            }
            Ok(output)
        }
        Node::Path(segments) => {
            let mut paths = inputs;
            for segment in segments {
                let mut next = Vec::new();
                for path in paths {
                    budget.tick(1)?;
                    let old = get_path(root, &path).unwrap_or(&Value::Null);
                    let keys = match segment {
                        Segment::Key(key) if old.is_null() || old.is_mapping() => {
                            budget.reserve(key.len() + std::mem::size_of::<Key>())?;
                            vec![Key::Field(key.clone())]
                        }
                        Segment::Index(index) if old.is_null() || old.is_sequence() => {
                            normalized_index(*index, old.as_sequence().map_or(0, Vec::len))
                                .map(|index| vec![Key::Index(index)])
                                .unwrap_or_default()
                        }
                        Segment::Each if old.is_sequence() || old.is_mapping() => {
                            members(old, budget)?
                                .into_iter()
                                .map(|(key, _)| key)
                                .collect()
                        }
                        _ => vec![],
                    };
                    for key in keys {
                        budget.reserve((path.len() + 1) * std::mem::size_of::<Key>())?;
                        for key in &path {
                            if let Key::Field(key) = key {
                                budget.reserve(key.len())?;
                            }
                        }
                        let mut selected = path.clone();
                        selected.push(key);
                        next.push(selected);
                    }
                }
                paths = next;
            }
            Ok(paths)
        }
        _ => Err(error("invalid provider override update target")),
    }
}
fn set_path(
    value: &mut Value,
    path: &[Key],
    replacement: Value,
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<()> {
    budget.tick(1)?;
    if depth > VALUE_DEPTH {
        return Err(error("provider override target depth exceeded"));
    }
    let Some((key, rest)) = path.split_first() else {
        *value = replacement;
        return Ok(());
    };
    match key {
        Key::Field(key) => {
            if value.is_null() {
                *value = Value::Mapping(Mapping::new());
            }
            if let Some(map) = value.as_mapping_mut() {
                if !map.contains_key(key.as_str()) {
                    budget.reserve(key.len() + 2 * std::mem::size_of::<Value>())?;
                    map.insert(Value::String(key.clone()), Value::Null);
                }
                set_path(
                    map.get_mut(key.as_str()).expect("inserted entry"),
                    rest,
                    replacement,
                    budget,
                    depth + 1,
                )?;
            }
        }
        Key::Index(index) => {
            if value.is_null() {
                *value = Value::Sequence(vec![]);
            }
            if let Some(array) = value.as_sequence_mut() {
                if *index >= array.len() {
                    let length = index
                        .checked_add(1)
                        .ok_or_else(|| error("provider override array budget exceeded"))?;
                    budget.tick(length - array.len())?;
                    budget.reserve(
                        (length - array.len())
                            .checked_mul(std::mem::size_of::<Value>())
                            .ok_or_else(|| error("provider override array budget exceeded"))?,
                    )?;
                    array.resize(length, Value::Null);
                }
                set_path(&mut array[*index], rest, replacement, budget, depth + 1)?;
            }
        }
    }
    Ok(())
}
fn delete_path(value: &mut Value, path: &[Key], budget: &mut Budget<'_>) -> Result<()> {
    budget.tick(1)?;
    let Some((key, rest)) = path.split_first() else {
        return Err(error("provider override cannot delete the root"));
    };
    match key {
        Key::Field(key) => {
            if let Some(map) = value.as_mapping_mut() {
                if rest.is_empty() {
                    map.remove(key.as_str());
                } else if let Some(value) = map.get_mut(key.as_str()) {
                    delete_path(value, rest, budget)?;
                }
            }
        }
        Key::Index(index) => {
            if let Some(array) = value.as_sequence_mut()
                && *index < array.len()
            {
                if rest.is_empty() {
                    array.remove(*index);
                } else {
                    delete_path(&mut array[*index], rest, budget)?;
                }
            }
        }
    }
    Ok(())
}

fn truthy(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
}
fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".into()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) if value.is_f64() => value.as_f64().map(float_text),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => Some(value.clone()),
        _ => None,
    }
}
fn float_text(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-Inf"
        } else {
            "+Inf"
        }
        .into();
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("float exponent");
    let exponent: i32 = exponent.parse().expect("numeric exponent");
    if !(-4..6).contains(&exponent) {
        format!("{mantissa}e{exponent:+03}")
    } else {
        value.to_string()
    }
}
fn text(value: &Value, budget: &mut Budget<'_>) -> Result<String> {
    if let Value::String(value) = value {
        budget.reserve(value.len())?;
        return Ok(value.clone());
    }
    if let Value::Number(number) = value
        && number.as_f64().is_some_and(|value| !value.is_finite())
    {
        let text = yaml_scalar(value, budget)?;
        budget.reserve(text.len())?;
        return Ok(text);
    }
    if let Some(text) = scalar_text(value) {
        budget.reserve(text.len())?;
        return Ok(text);
    }
    budget.measure(value, 0)?;
    let sorted = sorted_value(value, budget, 0)?;
    render(&sorted, budget)
}
fn render(value: &Value, budget: &mut Budget<'_>) -> Result<String> {
    let mut output = String::new();
    render_node(value, 0, false, &mut output, budget, 0)?;
    if output.ends_with('\n') {
        output.pop();
    }
    Ok(output)
}

fn render_node(
    value: &Value,
    indentation: usize,
    inline: bool,
    output: &mut String,
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<()> {
    budget.tick(1)?;
    if depth > VALUE_DEPTH {
        return Err(error("provider override value depth exceeded"));
    }
    let pad = |output: &mut String, budget: &mut Budget<'_>| {
        for _ in 0..indentation {
            append(output, " ", budget)?;
        }
        Ok::<_, VoleError>(())
    };
    match value {
        Value::Mapping(map) if !map.is_empty() => {
            let mut fields = members(value, budget)?;
            fields.sort_by(|(a, _), (b, _)| {
                let (Key::Field(a), Key::Field(b)) = (a, b) else {
                    unreachable!()
                };
                yaml_key_order(a, b)
            });
            for (index, (key, value)) in fields.into_iter().enumerate() {
                if !inline || index != 0 {
                    pad(output, budget)?;
                }
                let Key::Field(key) = key else { unreachable!() };
                let rendered = yaml_scalar(&Value::String(key), budget)?;
                append(output, &rendered, budget)?;
                append(output, ":", budget)?;
                if matches!(value, Value::Mapping(map) if !map.is_empty())
                    || matches!(value, Value::Sequence(items) if !items.is_empty())
                {
                    append(output, "\n", budget)?;
                    render_node(
                        value,
                        (indentation / 4 + 1) * 4,
                        false,
                        output,
                        budget,
                        depth + 1,
                    )?;
                } else {
                    append(output, " ", budget)?;
                    render_node(value, indentation, true, output, budget, depth + 1)?;
                }
            }
        }
        Value::Sequence(items) if !items.is_empty() => {
            for (index, value) in items.iter().enumerate() {
                if !inline || index != 0 {
                    pad(output, budget)?;
                }
                append(output, "- ", budget)?;
                render_node(value, indentation + 2, true, output, budget, depth + 1)?;
            }
        }
        Value::String(text)
            if text.contains('\n')
                && !text
                    .chars()
                    .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t')) =>
        {
            if !inline {
                pad(output, budget)?;
            }
            let suffix = if !text.ends_with('\n') {
                "-"
            } else if text.ends_with("\n\n") || text == "\n" {
                "+"
            } else {
                ""
            };
            let explicit_indent = text
                .lines()
                .find(|line| !line.is_empty())
                .is_some_and(|line| line.starts_with(' '));
            append(output, "|", budget)?;
            if explicit_indent {
                append(
                    output,
                    if indentation.is_multiple_of(4) {
                        "4"
                    } else {
                        "2"
                    },
                    budget,
                )?;
            }
            append(output, suffix, budget)?;
            append(output, "\n", budget)?;
            for line in text.split_inclusive('\n') {
                if line != "\n" {
                    for _ in 0..(indentation / 4 + 1) * 4 {
                        append(output, " ", budget)?;
                    }
                }
                append(output, line, budget)?;
                if !line.ends_with('\n') {
                    append(output, "\n", budget)?;
                }
            }
        }
        _ => {
            if !inline {
                pad(output, budget)?;
            }
            let rendered = yaml_scalar(value, budget)?;
            append(output, &rendered, budget)?;
            append(output, "\n", budget)?;
        }
    }
    Ok(())
}

fn yaml_scalar(value: &Value, budget: &mut Budget<'_>) -> Result<String> {
    if let Value::Number(number) = value {
        return Ok(if number.is_f64() {
            let number = number.as_f64().expect("float");
            if number.is_nan() {
                ".nan".into()
            } else if number.is_infinite() {
                if number.is_sign_negative() {
                    "-.inf"
                } else {
                    ".inf"
                }
                .into()
            } else {
                float_text(number)
            }
        } else {
            number.to_string()
        });
    }
    if let Value::String(text) = value {
        budget.reserve(text.len().saturating_mul(6).saturating_add(2))?;
        let lower = text.to_ascii_lowercase();
        let ambiguous = text.is_empty()
            || matches!(
                lower.as_str(),
                "y" | "n"
                    | "yes"
                    | "no"
                    | "on"
                    | "off"
                    | "true"
                    | "false"
                    | "null"
                    | "~"
                    | ".inf"
                    | "+.inf"
                    | "-.inf"
                    | ".nan"
            )
            || text.parse::<f64>().is_ok()
            || ["0x", "0X", "0o", "0O", "0b", "0B"].iter().any(|prefix| {
                text.strip_prefix(['+', '-'])
                    .unwrap_or(text)
                    .strip_prefix(prefix)
                    .is_some_and(|digits| {
                        !digits.is_empty()
                            && digits.bytes().all(|byte| match *prefix {
                                "0x" | "0X" => byte.is_ascii_hexdigit() || byte == b'_',
                                "0o" | "0O" => matches!(byte, b'0'..=b'7' | b'_'),
                                _ => matches!(byte, b'0' | b'1' | b'_'),
                            })
                    })
            })
            || (text.len() >= 10
                && text.as_bytes()[4] == b'-'
                && text.as_bytes()[7] == b'-'
                && text[..4].bytes().all(|byte| byte.is_ascii_digit()))
            || text
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '\u{a0}' | '\u{2028}' | '\u{2029}'));
        if ambiguous {
            let mut output = String::new();
            append(&mut output, "\"", budget)?;
            for character in text.chars() {
                let escaped = match character {
                    '\0' => Some(r"\0"),
                    '\u{7}' => Some(r"\a"),
                    '\u{8}' => Some(r"\b"),
                    '\t' => Some(r"\t"),
                    '\n' => Some(r"\n"),
                    '\u{b}' => Some(r"\v"),
                    '\u{c}' => Some(r"\f"),
                    '\r' => Some(r"\r"),
                    '\u{1b}' => Some(r"\e"),
                    '\u{85}' => Some(r"\N"),
                    '\u{a0}' => Some(r"\_"),
                    '\u{2028}' => Some(r"\L"),
                    '\u{2029}' => Some(r"\P"),
                    '"' => Some(r#"\""#),
                    '\\' => Some(r"\\"),
                    _ => None,
                };
                if let Some(escaped) = escaped {
                    append(&mut output, escaped, budget)?;
                } else if character.is_control() {
                    append(&mut output, &format!("\\x{:02X}", character as u32), budget)?;
                } else {
                    let mut encoded = [0; 4];
                    append(&mut output, character.encode_utf8(&mut encoded), budget)?;
                }
            }
            append(&mut output, "\"", budget)?;
            return Ok(output);
        }
    }
    let rendered = serde_yaml_ng::to_string(value)
        .map_err(|_| error("provider override value cannot be rendered"))?;
    budget.reserve(rendered.len())?;
    Ok(rendered.trim_end_matches('\n').into())
}

fn yaml_key_order(left: &str, right: &str) -> Ordering {
    let (mut left, mut right) = (left.as_bytes(), right.as_bytes());
    while let (Some(a), Some(b)) = (left.first(), right.first()) {
        if a.is_ascii_digit() && b.is_ascii_digit() {
            let left_end = left
                .iter()
                .position(|byte| !byte.is_ascii_digit())
                .unwrap_or(left.len());
            let right_end = right
                .iter()
                .position(|byte| !byte.is_ascii_digit())
                .unwrap_or(right.len());
            let (a, b) = (&left[..left_end], &right[..right_end]);
            let a = &a[a.iter().position(|byte| *byte != b'0').unwrap_or(a.len())..];
            let b = &b[b.iter().position(|byte| *byte != b'0').unwrap_or(b.len())..];
            let ordering = a
                .len()
                .cmp(&b.len())
                .then_with(|| a.cmp(b))
                .then_with(|| left_end.cmp(&right_end));
            if !ordering.is_eq() {
                return ordering;
            }
            left = &left[left_end..];
            right = &right[right_end..];
        } else {
            let ordering = a.cmp(b);
            if !ordering.is_eq() {
                return ordering;
            }
            left = &left[1..];
            right = &right[1..];
        }
    }
    left.len().cmp(&right.len())
}
fn sorted_value(value: &Value, budget: &mut Budget<'_>, depth: usize) -> Result<Value> {
    budget.tick(1)?;
    if depth > VALUE_DEPTH {
        return Err(error("provider override value depth exceeded"));
    }
    match value {
        Value::Mapping(_) => {
            let mut map = Mapping::new();
            for (key, value) in members(value, budget)? {
                let Key::Field(key) = key else { unreachable!() };
                budget.reserve(key.len() + 2 * std::mem::size_of::<Value>())?;
                map.insert(Value::String(key), sorted_value(value, budget, depth + 1)?);
            }
            Ok(Value::Mapping(map))
        }
        Value::Sequence(values) => Ok(Value::Sequence(
            values
                .iter()
                .map(|value| sorted_value(value, budget, depth + 1))
                .collect::<Result<Vec<_>>>()?,
        )),
        _ => budget.clone_value(value),
    }
}
fn equality(a: &Value, b: &Value) -> bool {
    if a.is_null() || b.is_null() {
        return a.is_null() && b.is_null();
    }
    if let (Value::Number(a), Value::Number(b)) = (a, b) {
        return a.is_f64() == b.is_f64() && a.as_f64() == b.as_f64();
    }
    scalar_text(a)
        .zip(scalar_text(b))
        .is_some_and(|(a, b)| a == b)
}
fn numeric(value: &Value) -> Result<f64> {
    value
        .as_f64()
        .ok_or_else(|| error("provider override operator requires numbers"))
}
fn scalar_order(a: &Value, b: &Value) -> Result<Ordering> {
    match (a, b) {
        (Value::Number(_), Value::Number(_)) => Ok(numeric(a)?
            .partial_cmp(&numeric(b)?)
            .unwrap_or(Ordering::Equal)),
        (Value::String(a), Value::String(b)) => Ok(a.cmp(b)),
        _ => Err(error(
            "provider override ordered comparison requires compatible scalars",
        )),
    }
}
fn sort_order(a: &Value, b: &Value) -> Ordering {
    fn rank(value: &Value) -> u8 {
        match value {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::Number(_) => 2,
            Value::String(_) => 3,
            _ => 4,
        }
    }
    rank(a).cmp(&rank(b)).then_with(|| match (a, b) {
        (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
        (Value::Number(_), Value::Number(_)) => a
            .as_f64()
            .unwrap_or(0.0)
            .partial_cmp(&b.as_f64().unwrap_or(0.0))
            .unwrap_or(Ordering::Equal),
        (Value::String(a), Value::String(b)) => a.cmp(b),
        _ => Ordering::Equal,
    })
}
fn binary(
    operator: Op,
    a: &Value,
    b: &Value,
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<Value> {
    budget.tick(1)?;
    if depth > VALUE_DEPTH {
        return Err(error("provider override value depth exceeded"));
    }
    match operator {
        Op::Eq => return Ok(Value::Bool(equality(a, b))),
        Op::Ne => return Ok(Value::Bool(!equality(a, b))),
        Op::And => return Ok(Value::Bool(truthy(a) && truthy(b))),
        Op::Or => return Ok(Value::Bool(truthy(a) || truthy(b))),
        Op::Lt | Op::Le | Op::Gt | Op::Ge => {
            if !matches!(
                a,
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
            ) || !matches!(
                b,
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
            ) {
                return Err(error(
                    "provider override ordered comparison requires scalars",
                ));
            }
            if a.is_null() || b.is_null() {
                return Ok(Value::Bool(
                    a.is_null() && b.is_null() && matches!(operator, Op::Le | Op::Ge),
                ));
            }
            let ordering = scalar_order(a, b)?;
            return Ok(Value::Bool(match operator {
                Op::Lt => ordering.is_lt(),
                Op::Le => !ordering.is_gt(),
                Op::Gt => ordering.is_gt(),
                _ => !ordering.is_lt(),
            }));
        }
        _ => {}
    }
    if matches!(operator, Op::Add | Op::Sub) && a.is_null() {
        return budget.clone_value(b);
    }
    if operator == Op::Mul && b.is_null() {
        return budget.clone_value(a);
    }
    if operator == Op::Mul && a.is_null() && (b.is_sequence() || b.is_mapping()) {
        return budget.clone_value(b);
    }
    if operator == Op::Add && b.is_null() && (a.is_string() || a.is_sequence()) {
        return budget.clone_value(a);
    }
    if operator == Op::Add && b.is_string() && !a.is_sequence() && !a.is_mapping() {
        let left = scalar_text(a)
            .ok_or_else(|| error("provider override string addition requires a scalar"))?;
        let mut output = String::new();
        append(&mut output, &left, budget)?;
        append(&mut output, b.as_str().expect("string"), budget)?;
        return Ok(Value::String(output));
    }
    if operator == Op::Add {
        match (a, b) {
            (Value::String(left), _) => {
                let Some(right) = scalar_text(b) else {
                    return Err(error("provider override string addition requires a scalar"));
                };
                let mut result = String::new();
                append(&mut result, left, budget)?;
                append(&mut result, &right, budget)?;
                return Ok(Value::String(result));
            }
            (Value::Sequence(left), Value::Sequence(right)) => {
                let mut values = left
                    .iter()
                    .map(|value| budget.clone_value(value))
                    .collect::<Result<Vec<_>>>()?;
                for value in right {
                    values.push(budget.clone_value(value)?);
                }
                return Ok(Value::Sequence(values));
            }
            (Value::Sequence(left), _) => {
                let mut values = left
                    .iter()
                    .map(|value| budget.clone_value(value))
                    .collect::<Result<Vec<_>>>()?;
                values.push(budget.clone_value(b)?);
                return Ok(Value::Sequence(values));
            }
            (Value::Mapping(left), Value::Mapping(right)) => {
                let Value::Mapping(mut result) = budget.clone_value(a)? else {
                    unreachable!()
                };
                for (key, value) in right {
                    result.insert(budget.clone_value(key)?, budget.clone_value(value)?);
                }
                let _ = left;
                return Ok(Value::Mapping(result));
            }
            _ => {}
        }
    }
    if operator == Op::Sub
        && let (Value::Sequence(left), Value::Sequence(right)) = (a, b)
    {
        let mut result = Vec::new();
        for value in left {
            if !right.iter().any(|other| value == other) {
                result.push(budget.clone_value(value)?);
            }
        }
        return Ok(Value::Sequence(result));
    }
    if operator == Op::Mul {
        if let (Value::Mapping(_), Value::Mapping(right)) = (a, b) {
            let Value::Mapping(mut result) = budget.clone_value(a)? else {
                unreachable!()
            };
            for (key, value) in right {
                let merged = if let Some(old) = result.get(key)
                    && old.is_mapping()
                    && value.is_mapping()
                {
                    binary(Op::Mul, old, value, budget, depth + 1)?
                } else {
                    budget.clone_value(value)?
                };
                result.insert(budget.clone_value(key)?, merged);
            }
            return Ok(Value::Mapping(result));
        }
        if a.is_sequence() && b.is_sequence() {
            return budget.clone_value(b);
        }
        let string_number = match (a, b) {
            (Value::String(text), Value::Number(number))
            | (Value::Number(number), Value::String(text)) => Some((text, number)),
            _ => None,
        };
        if let Some((text, number)) = string_number {
            let count = number
                .as_i64()
                .and_then(|number| usize::try_from(number).ok())
                .ok_or_else(|| {
                    error("provider override string repetition requires a nonnegative integer")
                })?;
            let bytes = text
                .len()
                .checked_mul(count)
                .ok_or_else(|| error("provider override output budget exceeded"))?;
            budget.reserve(bytes)?;
            return Ok(Value::String(text.repeat(count)));
        }
    }
    if operator == Op::Div
        && let (Value::String(text), Value::String(separator)) = (a, b)
    {
        return if text.is_empty() {
            Ok(Value::Sequence(Vec::new()))
        } else {
            split(text, separator, budget)
        };
    }
    if !a.is_number() || !b.is_number() {
        return Err(error(
            "provider override operator has incompatible operands",
        ));
    }
    if matches!(a, Value::Number(number) if !number.is_f64())
        && matches!(b, Value::Number(number) if !number.is_f64())
        && operator != Op::Div
    {
        // The reference dialect computes signed platform integers after a
        // float64 projection. Preserve its 64-bit arithmetic and wrap behavior.
        let integer = |value: &Value| -> Result<i64> {
            let value = numeric(value)?;
            Ok(
                if value >= 9_223_372_036_854_775_808.0 || value < -9_223_372_036_854_775_808.0 {
                    i64::MIN
                } else {
                    value as i64
                },
            )
        };
        let (a, b) = (integer(a)?, integer(b)?);
        let result = match operator {
            Op::Add => a.wrapping_add(b),
            Op::Sub => a.wrapping_sub(b),
            Op::Mul => a.wrapping_mul(b),
            Op::Mod if b == 0 => return Err(error("provider override cannot modulo integer zero")),
            Op::Mod if a == i64::MIN && b == -1 => 0,
            Op::Mod => a % b,
            _ => return Err(error("invalid provider override operator")),
        };
        return Ok(Value::Number(result.into()));
    }
    let (a, b) = (numeric(a)?, numeric(b)?);
    let number = match operator {
        Op::Add => a + b,
        Op::Sub => a - b,
        Op::Mul => a * b,
        Op::Div => a / b,
        Op::Mod => a % b,
        _ => return Err(error("invalid provider override operator")),
    };
    Ok(Value::Number(Number::from(number)))
}
fn split(text: &str, separator: &str, budget: &mut Budget<'_>) -> Result<Value> {
    let mut values = Vec::new();
    if text.is_empty() && separator.is_empty() {
        return Ok(Value::Sequence(values));
    }
    if separator.is_empty() {
        for ch in text.chars() {
            budget.reserve(ch.len_utf8() + std::mem::size_of::<Value>())?;
            values.push(Value::String(ch.to_string()));
        }
    } else {
        for part in text.split(separator) {
            budget.reserve(part.len() + std::mem::size_of::<Value>())?;
            values.push(Value::String(part.into()));
        }
    }
    Ok(Value::Sequence(values))
}
fn contains(
    container: &Value,
    wanted: &Value,
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<bool> {
    budget.tick(1)?;
    if depth > VALUE_DEPTH {
        return Err(error("provider override value depth exceeded"));
    }
    match (container, wanted) {
        (Value::String(container), Value::String(wanted)) => Ok(container.contains(wanted)),
        (Value::Mapping(container), Value::Mapping(wanted)) => {
            for (key, value) in wanted {
                let Some(other) = container.get(key) else {
                    return Ok(false);
                };
                if !contains(other, value, budget, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (Value::Sequence(container), Value::Sequence(wanted)) => {
            for value in wanted {
                let mut found = false;
                for other in container {
                    if contains(other, value, budget, depth + 1)? {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (Value::Sequence(container), wanted) => {
            for value in container {
                if contains(value, wanted, budget, depth + 1)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        (Value::Number(_), Value::Number(_)) => Ok(equality(container, wanted)),
        _ => Ok(container == wanted),
    }
}

fn transform(
    args: &[Node],
    inputs: Vec<Value>,
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<Vec<Value>> {
    let mut inputs = Some(inputs);
    let mut output = Vec::new();
    for (index, node) in args.iter().enumerate() {
        let batch = if index + 1 == args.len() {
            inputs.take().expect("last transform owns inputs")
        } else {
            inputs
                .as_ref()
                .expect("unconsumed inputs")
                .iter()
                .map(|value| budget.clone_value(value))
                .collect::<Result<Vec<_>>>()?
        };
        let values = evaluate(node, batch, budget, depth + 1)?;
        budget.reserve(values.len().saturating_mul(std::mem::size_of::<Value>()))?;
        output.extend(values);
    }
    Ok(output)
}

fn call(
    name: &str,
    args: &[Node],
    input: &Value,
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<Vec<Value>> {
    budget.tick(1)?;
    if depth > PARSE_DEPTH {
        return Err(error("provider override evaluation depth exceeded"));
    }
    if name == "select" {
        return if one(&args[0], input, budget, depth)?.is_some_and(|value| truthy(&value)) {
            Ok(vec![budget.clone_value(input)?])
        } else {
            Ok(vec![])
        };
    }
    if [
        "map",
        "map_values",
        "filter",
        "any_c",
        "all_c",
        "with_entries",
    ]
    .contains(&name)
    {
        if name == "with_entries" {
            if !input.is_mapping() {
                return Err(error("provider override with_entries requires a mapping"));
            }
            let entries = entries(input, budget)?;
            let mut result = Vec::new();
            for entry in entries {
                result.extend(transform(args, vec![entry], budget, depth + 1)?);
            }
            return Ok(vec![from_entries(&Value::Sequence(result), budget)?]);
        }
        if matches!(name, "any_c" | "all_c") && !input.is_sequence() {
            return Err(error(
                "provider override conditional query requires an array",
            ));
        }
        let members = members(input, budget)?;
        if name == "map" {
            let inputs = members
                .iter()
                .map(|(_, value)| budget.clone_value(value))
                .collect::<Result<Vec<_>>>()?;
            return Ok(vec![Value::Sequence(transform(
                args,
                inputs,
                budget,
                depth + 1,
            )?)]);
        }
        if matches!(name, "any_c" | "all_c") {
            let result = name == "all_c";
            for (_, value) in members {
                let value = budget.clone_value(value)?;
                let outputs = transform(args, vec![value], budget, depth + 1)?;
                let Some(first) = outputs.first() else {
                    continue;
                };
                let matched = truthy(first);
                if name == "any_c" && matched || name == "all_c" && !matched {
                    return Ok(vec![Value::Bool(matched)]);
                }
            }
            return Ok(vec![Value::Bool(result)]);
        }
        if name == "filter" {
            let mut output = Vec::new();
            for (_, value) in members {
                let copy = budget.clone_value(value)?;
                if transform(args, vec![copy], budget, depth + 1)?
                    .iter()
                    .any(truthy)
                {
                    output.push(budget.clone_value(value)?);
                }
            }
            return Ok(vec![Value::Sequence(output)]);
        }
        let mut output = budget.clone_value(input)?;
        for (key, value) in members {
            let copy = budget.clone_value(value)?;
            if let Some(result) = transform(args, vec![copy], budget, depth + 1)?
                .into_iter()
                .next()
            {
                set_path(&mut output, &[key], result, budget, 0)?;
            }
        }
        return Ok(vec![output]);
    }
    let mut arguments = Vec::new();
    for argument in args {
        let Some(value) = one(argument, input, budget, depth)? else {
            return Ok(vec![]);
        };
        arguments.push(value);
    }
    let output = match name {
        "length" => Value::Number(
            match input {
                Value::Null => 0,
                Value::Sequence(value) => value.len(),
                Value::Mapping(value) => value.len(),
                _ => scalar_text(input)
                    .ok_or_else(|| error("invalid provider override length input"))?
                    .len(),
            }
            .into(),
        ),
        "keys" => Value::Sequence(
            members(input, budget)?
                .into_iter()
                .map(|(key, _)| match key {
                    Key::Field(key) => Value::String(key),
                    Key::Index(index) => Value::Number(index.into()),
                })
                .collect(),
        ),
        "has" => Value::Bool(match input {
            Value::Mapping(map) => map.contains_key(Value::String(
                arguments[0]
                    .as_str()
                    .ok_or_else(|| error("provider override mapping key must be a string"))?
                    .into(),
            )),
            Value::Sequence(values) => arguments[0]
                .as_i64()
                .and_then(|index| normalized_index(index, values.len()))
                .is_some_and(|index| index < values.len()),
            _ => false,
        }),
        "contains" => {
            let compatible = match input {
                Value::Mapping(_) => arguments[0].is_mapping(),
                Value::Sequence(_) => arguments[0].is_sequence(),
                Value::String(_) => arguments[0].is_string(),
                _ => !arguments[0].is_mapping() && !arguments[0].is_sequence(),
            };
            if !compatible {
                return Err(error(
                    "provider override contains requires compatible value types",
                ));
            }
            Value::Bool(contains(input, &arguments[0], budget, 0)?)
        }
        "reverse" => {
            let Some(values) = input.as_sequence() else {
                return Err(error("provider override reverse requires an array"));
            };
            Value::Sequence(
                values
                    .iter()
                    .rev()
                    .map(|value| budget.clone_value(value))
                    .collect::<Result<Vec<_>>>()?,
            )
        }
        "sort" => {
            let Some(values) = input.as_sequence() else {
                return Err(error("provider override sort requires an array"));
            };
            if values.iter().any(|value| {
                value.is_sequence() || value.is_mapping() || matches!(value, Value::Tagged(_))
            }) {
                return Err(error("provider override sort requires scalar values"));
            }
            budget.tick(
                values
                    .len()
                    .saturating_mul(1 + values.len().checked_ilog2().unwrap_or(0) as usize),
            )?;
            let mut values = values
                .iter()
                .map(|value| budget.clone_value(value))
                .collect::<Result<Vec<_>>>()?;
            values.sort_by(sort_order);
            Value::Sequence(values)
        }
        "unique" => {
            let Some(values) = input.as_sequence() else {
                return Err(error("provider override unique requires an array"));
            };
            let mut seen = std::collections::BTreeSet::new();
            let mut output = Vec::new();
            for value in values {
                let key = if let Some(key) = scalar_text(value) {
                    budget.reserve(key.len())?;
                    key
                } else {
                    let mut key = text(value, budget)?;
                    append(&mut key, "\n", budget)?;
                    key
                };
                if seen.insert(key) {
                    output.push(budget.clone_value(value)?);
                }
            }
            Value::Sequence(output)
        }
        "flatten" => {
            let Some(values) = input.as_sequence() else {
                return Err(error("provider override flatten requires an array"));
            };
            let flatten_depth = if arguments.is_empty() {
                VALUE_DEPTH
            } else {
                arguments[0]
                    .as_i64()
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(|| {
                        error("provider override flatten depth must be a nonnegative integer")
                    })?
            };
            let mut output = Vec::new();
            flatten(values, flatten_depth, &mut output, budget, 0)?;
            Value::Sequence(output)
        }
        "any" | "all" => {
            let Some(values) = input.as_sequence() else {
                return Err(error("provider override query requires an array"));
            };
            Value::Bool(if name == "any" {
                values.iter().any(truthy)
            } else {
                values.iter().all(truthy)
            })
        }
        "to_entries" => {
            if input.is_null() {
                return Ok(vec![]);
            }
            Value::Sequence(entries(input, budget)?)
        }
        "from_entries" => from_entries(input, budget)?,
        "test" => {
            let pattern = arguments[0]
                .as_str()
                .ok_or_else(|| error("provider override test pattern must be a string"))?;
            if arguments
                .get(1)
                .is_some_and(|flags| flags.as_str() != Some("g"))
            {
                return Err(error("unsupported provider override regex flags"));
            }
            let input = input
                .as_str()
                .ok_or_else(|| error("provider override test requires a string"))?;
            let regex = budget.regex(pattern)?;
            budget.tick(input.len() / 64 + 1)?;
            Value::Bool(regex.is_match(input))
        }
        "sub" => {
            let pattern = arguments[0]
                .as_str()
                .ok_or_else(|| error("provider override replacement pattern must be a string"))?;
            let target = arguments[1]
                .as_str()
                .ok_or_else(|| error("provider override replacement target must be a string"))?;
            let input = input
                .as_str()
                .ok_or_else(|| error("provider override replacement requires a string"))?;
            let regex = budget.regex(pattern)?;
            let mut output = String::new();
            let mut last = 0;
            for captures in regex.captures_iter(input) {
                budget.tick(1)?;
                let matched = captures.get(0).expect("whole regex match");
                append(&mut output, &input[last..matched.start()], budget)?;
                expand_replacement(target, &captures, &mut output, budget)?;
                last = matched.end();
            }
            append(&mut output, &input[last..], budget)?;
            Value::String(output)
        }
        "split" => {
            if input.is_null() {
                return Ok(vec![]);
            }
            let separator = arguments[0]
                .as_str()
                .ok_or_else(|| error("provider override separator must be a string"))?;
            split(
                input
                    .as_str()
                    .ok_or_else(|| error("provider override split requires a string"))?,
                separator,
                budget,
            )?
        }
        "join" => {
            let separator = arguments[0]
                .as_str()
                .ok_or_else(|| error("provider override separator must be a string"))?;
            let values = input
                .as_sequence()
                .ok_or_else(|| error("provider override join requires an array"))?;
            let mut output = String::new();
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    append(&mut output, separator, budget)?;
                }
                if !value.is_null()
                    && let Some(value) = scalar_text(value)
                {
                    append(&mut output, &value, budget)?;
                }
            }
            Value::String(output)
        }
        "upcase" | "downcase" | "trim" => {
            let value = input
                .as_str()
                .ok_or_else(|| error("provider override string transform requires a string"))?;
            budget.reserve(value.len().saturating_mul(3))?;
            Value::String(match name {
                "upcase" => value.to_uppercase(),
                "downcase" => value.to_lowercase(),
                _ => value.trim().to_owned(),
            })
        }
        "tostring" => {
            if let Value::String(text) = input {
                budget.reserve(text.len())?;
                Value::String(text.clone())
            } else {
                let sorted = sorted_value(input, budget, 0)?;
                Value::String(render(&sorted, budget)?)
            }
        }
        "tonumber" => {
            if input.is_number() {
                budget.clone_value(input)?
            } else {
                number_value(
                    input.as_str().ok_or_else(|| {
                        error("provider override tonumber requires a string or number")
                    })?,
                    true,
                )?
            }
        }
        "type" => Value::String(
            match input {
                Value::Null => "!!null",
                Value::Bool(_) => "!!bool",
                Value::Number(number) if number.is_f64() => "!!float",
                Value::Number(_) => "!!int",
                Value::String(_) => "!!str",
                Value::Sequence(_) => "!!seq",
                Value::Mapping(_) => "!!map",
                Value::Tagged(_) => {
                    return Err(error("provider override does not support YAML tags"));
                }
            }
            .into(),
        ),
        "not" => Value::Bool(!truthy(input)),
        _ => return Err(error("unsupported provider override function")),
    };
    budget.measure(&output, 0)?;
    Ok(vec![output])
}
fn entries(input: &Value, budget: &mut Budget<'_>) -> Result<Vec<Value>> {
    let mut output = Vec::new();
    for (key, value) in members(input, budget)? {
        budget.reserve(2 * std::mem::size_of::<Value>())?;
        let key = match key {
            Key::Field(key) => Value::String(key),
            Key::Index(index) => Value::Number(index.into()),
        };
        let mut entry = Mapping::new();
        entry.insert("key".into(), key);
        entry.insert("value".into(), budget.clone_value(value)?);
        output.push(Value::Mapping(entry));
    }
    Ok(output)
}
fn from_entries(input: &Value, budget: &mut Budget<'_>) -> Result<Value> {
    let array = input
        .as_sequence()
        .ok_or_else(|| error("provider override from_entries requires an array"))?;
    let mut map = Mapping::new();
    for entry in array {
        budget.tick(1)?;
        let entry = entry
            .as_mapping()
            .ok_or_else(|| error("provider override entries must be mappings"))?;
        let key = entry
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| error("provider override entry key must be a string"))?;
        let value = entry
            .get("value")
            .ok_or_else(|| error("provider override entry requires a value"))?;
        budget.reserve(key.len() + std::mem::size_of::<Value>() * 2)?;
        map.insert(key.into(), budget.clone_value(value)?);
    }
    Ok(Value::Mapping(map))
}
fn flatten(
    values: &[Value],
    limit: usize,
    output: &mut Vec<Value>,
    budget: &mut Budget<'_>,
    depth: usize,
) -> Result<()> {
    budget.tick(1)?;
    if depth > VALUE_DEPTH {
        return Err(error("provider override value depth exceeded"));
    }
    for value in values {
        if limit != 0
            && let Value::Sequence(nested) = value
        {
            flatten(nested, limit - 1, output, budget, depth + 1)?;
        } else {
            output.push(budget.clone_value(value)?);
        }
    }
    Ok(())
}
fn expand_replacement(
    target: &str,
    captures: &regex::Captures<'_>,
    output: &mut String,
    budget: &mut Budget<'_>,
) -> Result<()> {
    let mut cursor = 0;
    while cursor < target.len() {
        let rest = &target[cursor..];
        if let Some(index) = rest.find('$') {
            append(output, &rest[..index], budget)?;
            cursor += index + 1;
            if target[cursor..].starts_with('$') {
                append(output, "$", budget)?;
                cursor += 1;
                continue;
            }
            let braced = target[cursor..].starts_with('{');
            let start = cursor + usize::from(braced);
            let mut end = start;
            for character in target[start..].chars() {
                if !character.is_alphanumeric() && character != '_' {
                    break;
                }
                end += character.len_utf8();
            }
            if end == start || (braced && !target[end..].starts_with('}')) {
                append(output, "$", budget)?;
                continue;
            }
            let key = &target[start..end];
            let capture = (!key.starts_with('0') || key.len() == 1)
                .then(|| key.parse::<usize>().ok())
                .flatten()
                .and_then(|index| captures.get(index))
                .or_else(|| captures.name(key));
            if let Some(capture) = capture {
                append(output, capture.as_str(), budget)?;
            }
            cursor = end + usize::from(braced);
        } else {
            append(output, rest, budget)?;
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(input: &str, expression: &str) -> Value {
        let mut value: Value = serde_yaml_ng::from_str(input).unwrap();
        Expr::parse(expression)
            .unwrap()
            .apply(&mut value, &mut Budget::new(None))
            .unwrap();
        value
    }
    #[test]
    fn transforms_preserve_stream_order_and_update_context() {
        let result = run(
            "name: ' q '\nitems: [{name: one, port: 7, enabled: true}, {name: two, port: 9, enabled: false}]",
            r#".name |= (trim | upcase) | .pairs = [.items[] | (.name, .port)] | (.items[] | select(.enabled) | .port) += 2 | .label = "\(.name):\(.items[-1].port)""#,
        );
        assert_eq!(result["name"], Value::String("Q".into()));
        assert_eq!(
            result["pairs"],
            serde_yaml_ng::from_str::<Value>("[one, two, 7, 9]").unwrap()
        );
        assert_eq!(result["items"][0]["port"], Value::Number(9.into()));
        assert_eq!(result["label"], Value::String("Q:9".into()));
    }
    #[test]
    fn collection_operations_and_original_index_deletion() {
        let result = run(
            "values: [6, 8, 10, 12]\noptions: {c: 3, a: 1}\ngrid: [1, [2, [3]]]",
            r#"del(.values[0], .values[2]) | .options |= with_entries(.key |= upcase) | .grid |= flatten(1) | .numbers = (.options | map(. + 4)) | .has = (.numbers | any_c(. > 5))"#,
        );
        assert_eq!(
            result["values"],
            serde_yaml_ng::from_str::<Value>("[8,12]").unwrap()
        );
        assert_eq!(result["options"]["A"], Value::Number(1.into()));
        assert_eq!(
            result["grid"],
            serde_yaml_ng::from_str::<Value>("[1,2,[3]]").unwrap()
        );
        assert_eq!(
            result["numbers"],
            serde_yaml_ng::from_str::<Value>("[5,7]").unwrap()
        );
        assert_eq!(result["has"], Value::Bool(true));
    }
    #[test]
    fn collection_predicates_short_circuit_and_preserve_yaml_values() {
        let result = run(
            "name: fixture\n",
            r#".any = (["yes", {}] | any_c(contains("yes"))) | .all = (["no", {}] | all_c(contains("yes"))) | .nested = ([["a"]] | contains(["a"])) | .empty = (("" / ",") | length) | .split = ("" | split(",") | length) | .unique = (["a: b", {"a": "b"}] | unique | length) | .mapped = (["a", "b"] | map(.; upcase)) | .nan = ("NaN" | tonumber | tostring) | .nan_gt = (("NaN" | tonumber) > 1) | .nan_le = (("NaN" | tonumber) <= 1) | .nan_sort = ([("NaN" | tonumber),1] | sort | .[0] | tostring) | .null_gt = null > 1"#,
        );
        assert_eq!(result["any"], Value::Bool(true));
        assert_eq!(result["all"], Value::Bool(false));
        assert_eq!(result["nested"], Value::Bool(true));
        assert_eq!(result["empty"], Value::Number(0.into()));
        assert_eq!(result["nan"], Value::String(".nan".into()));
        assert_eq!(result["nan_gt"], Value::Bool(false));
        assert_eq!(result["nan_le"], Value::Bool(true));
        assert_eq!(result["nan_sort"], Value::String(".nan".into()));
        assert_eq!(result["null_gt"], Value::Bool(false));
        assert_eq!(result["split"], Value::Number(1.into()));
        assert_eq!(result["unique"], Value::Number(2.into()));
        assert_eq!(
            result["mapped"],
            serde_yaml_ng::from_str::<Value>("[a,b,A,B]").unwrap()
        );
        for source in [
            r#".x = ([{"Key": "name", "value": 1}] | from_entries)"#,
            r#".x = ([{"key": "name"}] | from_entries)"#,
            ".x = null > []",
        ] {
            let mut value: Value = serde_yaml_ng::from_str("name: fixture").unwrap();
            let original = value.clone();
            assert!(
                Expr::parse(source)
                    .unwrap()
                    .apply(&mut value, &mut Budget::new(None))
                    .is_err()
            );
            assert_eq!(value, original);
        }
    }

    #[test]
    fn budgets_are_checked_before_growth_and_candidates_are_atomic() {
        let mut value: Value = serde_yaml_ng::from_str("name: keeper").unwrap();
        let original = value.clone();
        let expression =
            Expr::parse(r#".name = "changed" | .slots[9223372036854775807] = true"#).unwrap();
        assert!(
            expression
                .apply(&mut value, &mut Budget::new(None))
                .is_err()
        );
        assert_eq!(value, original);
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            Expr::parse(".udp = true")
                .unwrap()
                .apply(&mut value, &mut Budget::new(Some(&cancel)))
                .is_err()
        );
        assert!(Expr::parse("del(.)").is_err());
        assert!(Expr::parse("env(SECRET)").is_err());
    }
    #[test]
    fn scalars_functions_and_uncollected_streams_have_explicit_behavior() {
        let result = run(
            "name: eu-7\nvalues: [2, '2', null, true]\noptions: {x: 4}",
            r#".name |= sub("eu-", "EU/") | .parts = (.name | split("/")) | .joined = (.parts | join(":")) | .seen = (.joined | test("^EU", "g")) | .count = (.joined | length) | .kind = (.count | type) | .has = (.options | has("x")) | .contained = (.options | contains({"x": 4})) | .distinct = (.values | unique) | .entries = (.options | to_entries | from_entries) | .empty = ([] | sort) | .integer = ("0o21" | tonumber) | .repeat = "z" * 3 | .fallback = false // 9 | .ratio = 7 / 2 | .ok = (.count >= 3 and (.seen | not) == false) | .absent = (select(false)) | .stream = {"gone": select(false), "last": (.values[])}"#,
        );
        assert_eq!(result["joined"], Value::String("EU:7".into()));
        assert_eq!(result["seen"], Value::Bool(true));
        assert_eq!(result["kind"], Value::String("!!int".into()));
        assert_eq!(result["entries"], result["options"]);
        assert_eq!(result["integer"], Value::Number(17.into()));
        assert_eq!(result["repeat"], Value::String("zzz".into()));
        assert_eq!(result["ratio"], Value::Number(Number::from(3.5)));
        assert_eq!(result["ok"], Value::Bool(true));
        assert!(result.get("absent").is_none());
        assert!(result["stream"].get("gone").is_none());
        assert_eq!(result["stream"]["last"], Value::Bool(true));
        assert!(Expr::parse(".enabled = true and false").is_err());
        assert!(Expr::parse(r#".name |= test("[")"#).is_err());
        let mut value: Value = serde_yaml_ng::from_str("values: [1, 2]").unwrap();
        assert!(
            Expr::parse(".result = (.values[])")
                .unwrap()
                .apply(&mut value, &mut Budget::new(None))
                .is_err()
        );
    }

    #[test]
    fn scalar_rendering_and_regex_replacements_follow_the_value_contract() {
        let result = run(
            "name: eu-8\noptions: {z: [1, 2], a: true}\nnumber: 1000000.0",
            r#".name |= sub("(?P<area>eu)-([0-9])", "${area}/$2/$$/$02/$2z") | .yaml = (.options | tostring) | .text = "\(.number)" | .ascii = ("１２" | test("\\d")) | .quoted = ("a.b" | test("\\Qa.b\\E")) | .tags = [(1 | type), (1.0 | type), ((1 / 0) | tostring), ((0 / 0) | tostring)] | .collected = [(.options[] | (., type))]"#,
        );
        assert_eq!(result["name"], Value::String("eu/8/$//".into()));
        assert_eq!(
            result["yaml"],
            Value::String("a: true\nz:\n    - 1\n    - 2".into())
        );
        assert_eq!(result["text"], Value::String("1e+06".into()));
        assert_eq!(result["ascii"], Value::Bool(false));
        assert_eq!(result["quoted"], Value::Bool(true));
        assert_eq!(
            result["tags"],
            serde_yaml_ng::from_str::<Value>("['!!int', '!!float', '.inf', '.nan']").unwrap()
        );
        assert_eq!(result["collected"].as_sequence().unwrap().len(), 4);
    }
}
