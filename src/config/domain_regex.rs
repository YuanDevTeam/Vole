//! Independent bounded DOMAIN-REGEX adapter. No GeoSite or name-filter policy.
use super::{Result, VoleError};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const PATTERN_BYTES: usize = 4096;
const AST_NODES: usize = 512;
const AST_DEPTH: usize = 32;
const REPEAT_BOUND: usize = 1024;
const COMPILED_BYTES: usize = 512 * 1024;
const DOMAIN_BYTES: usize = 253;
const CALL_BACKTRACKS: usize = 2048;
const DECISION_BACKTRACKS: usize = 64 * 1024;
const DECISION_WORK: u64 = 64 * 1024 * 1024;
const DECISION_MATCH_TIME: Duration = Duration::from_millis(2);

fn invalid(message: &'static str) -> VoleError {
    VoleError::InvalidConfig(message.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchFailure {
    Cancelled,
    Budget,
    InvalidInput,
    Engine,
}
impl fmt::Display for MatchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "domain rule evaluation cancelled",
            Self::Budget => "domain rule execution budget exceeded",
            Self::InvalidInput => "domain rule input exceeds the supported boundary",
            Self::Engine => "domain rule evaluation failed",
        })
    }
}
impl std::error::Error for MatchFailure {}

/// One owned value per complete decision, including suspended DNS traversal.
/// No Clone: recursive rules, provider predicates and retries borrow this value.
pub(crate) struct DecisionBudget {
    work: u64,
    backtracks: usize,
    match_time: Duration,
    failure: Option<MatchFailure>,
    cancellation: Vec<CancellationToken>,
    deadline: Option<Instant>,
}
impl Default for DecisionBudget {
    fn default() -> Self {
        Self::new()
    }
}
impl DecisionBudget {
    pub(crate) fn new() -> Self {
        Self {
            work: DECISION_WORK,
            backtracks: DECISION_BACKTRACKS,
            match_time: Duration::ZERO,
            failure: None,
            cancellation: Vec::new(),
            deadline: None,
        }
    }
    fn fail<T>(&mut self, failure: MatchFailure) -> std::result::Result<T, MatchFailure> {
        let failure = *self.failure.get_or_insert(failure);
        Err(failure)
    }
    pub(crate) fn check(
        &mut self,
        cancel: Option<&CancellationToken>,
    ) -> std::result::Result<(), MatchFailure> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        if cancel.is_some_and(CancellationToken::is_cancelled)
            || self
                .cancellation
                .iter()
                .any(CancellationToken::is_cancelled)
        {
            return self.fail(MatchFailure::Cancelled);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return self.fail(MatchFailure::Budget);
        }
        Ok(())
    }
    /// Call once for every predicate/program visit, including non-regex rules.
    pub(crate) fn visit(
        &mut self,
        cancel: Option<&CancellationToken>,
    ) -> std::result::Result<(), MatchFailure> {
        self.reserve(1, 0, cancel)
    }
    fn reserve(
        &mut self,
        work: u64,
        backtracks: usize,
        cancel: Option<&CancellationToken>,
    ) -> std::result::Result<(), MatchFailure> {
        self.check(cancel)?;
        let (Some(work), Some(backtracks)) = (
            self.work.checked_sub(work),
            self.backtracks.checked_sub(backtracks),
        ) else {
            return self.fail(MatchFailure::Budget);
        };
        self.work = work;
        self.backtracks = backtracks;
        Ok(())
    }
    fn finish(
        &mut self,
        duration: Duration,
        cancel: Option<&CancellationToken>,
    ) -> std::result::Result<(), MatchFailure> {
        self.match_time = self.match_time.saturating_add(duration);
        if self.match_time > DECISION_MATCH_TIME {
            return self.fail(MatchFailure::Budget);
        }
        self.check(cancel)
    }
}

/// A decision-local budget shared by contexts, candidates and lazy DNS continuation.
/// Synchronous matching holds the lock only while consuming the budget.
#[derive(Clone)]
pub struct RuleDecision(Arc<std::sync::Mutex<DecisionBudget>>);
tokio::task_local! { static ACTIVE_DECISION: RuleDecision; }
impl Default for RuleDecision {
    fn default() -> Self {
        ACTIVE_DECISION
            .try_with(Clone::clone)
            .unwrap_or_else(|_| Self(Arc::new(std::sync::Mutex::new(DecisionBudget::new()))))
    }
}
impl fmt::Debug for RuleDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuleDecision { .. }")
    }
}
// Evaluation accounting does not change the value identity of a routing context.
impl PartialEq for RuleDecision {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for RuleDecision {}
impl RuleDecision {
    pub(crate) async fn scope<F: std::future::Future>(&self, future: F) -> F::Output {
        ACTIVE_DECISION.scope(self.clone(), future).await
    }
    pub(crate) fn check(&self) -> std::result::Result<(), MatchFailure> {
        self.with(|budget| budget.check(None))
    }
    pub(crate) fn visit(&self) -> std::result::Result<(), MatchFailure> {
        self.with(|budget| budget.visit(None))
    }
    pub(crate) fn with<T>(
        &self,
        f: impl FnOnce(&mut DecisionBudget) -> std::result::Result<T, MatchFailure>,
    ) -> std::result::Result<T, MatchFailure> {
        let mut budget = self.0.lock().map_err(|_| MatchFailure::Engine)?;
        f(&mut budget)
    }
    pub(crate) fn set_cancellation(&self, cancellation: CancellationToken) {
        if let Ok(mut budget) = self.0.lock()
            && !budget.cancellation.contains(&cancellation)
        {
            if budget.cancellation.len() >= 64 {
                budget.failure.get_or_insert(MatchFailure::Budget);
            } else {
                budget.cancellation.push(cancellation);
            }
        }
    }
    pub(crate) fn set_deadline(&self, deadline: Instant) {
        if let Ok(mut budget) = self.0.lock() {
            budget.deadline = Some(budget.deadline.map_or(deadline, |old| old.min(deadline)));
        }
    }
    pub(crate) fn linear(
        &self,
        source_bytes: usize,
        input_bytes: usize,
        f: impl FnOnce() -> bool,
    ) -> std::result::Result<bool, MatchFailure> {
        self.with(|budget| {
            budget.reserve(
                (source_bytes as u64 + 1).saturating_mul(input_bytes as u64 + 1),
                0,
                None,
            )?;
            let started = Instant::now();
            let matched = f();
            budget.finish(started.elapsed(), None)?;
            Ok(matched)
        })
    }
}

/// Payload identity is preserved; pattern text is deliberately hidden in Debug/errors.
#[derive(Clone)]
pub struct DomainRegex(Arc<Compiled>);
struct Compiled {
    source: Arc<str>,
    weight: u64,
    engine: Engine,
}
enum Engine {
    Linear(regex::Regex),
    Complex(fancy_regex::Regex),
}
impl fmt::Debug for DomainRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DomainRegex { .. }")
    }
}
impl PartialEq for DomainRegex {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for DomainRegex {}
impl DomainRegex {
    pub fn new(pattern: &str) -> Result<Self> {
        if pattern.len() > PATTERN_BYTES {
            return Err(invalid("DOMAIN-REGEX compilation budget exceeded"));
        }
        let translated = common_dialect(pattern)?;
        let (translated, _) = capture_dialect(&translated)?;
        let tree = fancy_regex::Expr::parse_tree(&translated)
            .map_err(|_| invalid("invalid or unsupported DOMAIN-REGEX syntax"))?;
        let (nodes, weight, _) = inspect(&tree.expr)?;
        let engine = if let Ok(regex) = regex::RegexBuilder::new(&translated)
            .case_insensitive(true)
            .nest_limit(AST_DEPTH as u32)
            .size_limit(COMPILED_BYTES)
            .dfa_size_limit(COMPILED_BYTES)
            .build()
        {
            Engine::Linear(regex)
        } else {
            let fragment_bytes = (COMPILED_BYTES / nodes.max(1)).max(8192);
            let regex = fancy_regex::RegexBuilder::new(&translated)
                .case_insensitive(true)
                .backtrack_limit(CALL_BACKTRACKS)
                .seek(false)
                .delegate_size_limit(fragment_bytes)
                .delegate_dfa_size_limit(fragment_bytes)
                .build()
                .map_err(|_| invalid("invalid or unsupported DOMAIN-REGEX syntax"))?;
            Engine::Complex(regex)
        };
        Ok(Self(Arc::new(Compiled {
            source: Arc::from(pattern),
            weight,
            engine,
        })))
    }
    pub fn as_str(&self) -> &str {
        &self.0.source
    }
    pub fn is_match(
        &self,
        domain: &str,
        decision: &RuleDecision,
    ) -> std::result::Result<bool, MatchFailure> {
        decision.with(|budget| self.match_bounded(domain, budget, None))
    }
    pub(crate) fn is_match_process(
        &self,
        value: &str,
        decision: &RuleDecision,
    ) -> std::result::Result<bool, MatchFailure> {
        decision.with(|budget| self.match_input(value, budget, None, false))
    }
    fn match_bounded(
        &self,
        domain: &str,
        budget: &mut DecisionBudget,
        cancel: Option<&CancellationToken>,
    ) -> std::result::Result<bool, MatchFailure> {
        self.match_input(domain, budget, cancel, true)
    }
    fn match_input(
        &self,
        domain: &str,
        budget: &mut DecisionBudget,
        cancel: Option<&CancellationToken>,
        dns: bool,
    ) -> std::result::Result<bool, MatchFailure> {
        budget.check(cancel)?;
        if domain.is_empty()
            || domain.len()
                > if dns {
                    DOMAIN_BYTES
                } else {
                    super::process::MAX_PROCESS_TEXT
                }
            || (dns && (!domain.is_ascii() || domain.bytes().any(|b| b.is_ascii_control())))
            || domain.contains('\0')
        {
            return budget.fail(MatchFailure::InvalidInput);
        }
        let complex = matches!(self.0.engine, Engine::Complex(_));
        let work = self.0.weight.saturating_mul(domain.len() as u64 + 1);
        // fancy exposes only a per-regex backtrack bound, not actual steps or
        // a caller-owned counter. Reserve its worst-case quota before execution.
        // Reserving all of it prevents each rule from receiving a new total budget.
        budget.reserve(work, if complex { CALL_BACKTRACKS + 1 } else { 0 }, cancel)?;
        let started = Instant::now();
        let result = match &self.0.engine {
            Engine::Linear(regex) => Ok(regex.is_match(domain)),
            Engine::Complex(regex) => regex.is_match(domain).map_err(|error| {
                if matches!(
                    error,
                    fancy_regex::Error::RuntimeError(
                        fancy_regex::RuntimeError::BacktrackLimitExceeded
                    )
                ) {
                    MatchFailure::Budget
                } else {
                    MatchFailure::Engine
                }
            }),
        };
        // Post-call accounting is not preemptive: cancellation/elapsed guards
        // cannot interrupt the synchronous third-party VM in the current API.
        budget.finish(started.elapsed(), cancel)?;
        if let Err(failure) = result {
            return budget.fail(failure);
        }
        result
    }
}

/// A small independent lexical compatibility fence, not a .NET parser.
/// The third-party public AST validates the accepted grammar afterward.
pub(super) fn common_dialect(pattern: &str) -> Result<String> {
    let bytes = pattern.as_bytes();
    let mut output = String::with_capacity(pattern.len());
    let (mut index, mut in_class, mut depth) = (0, false, 0_usize);
    let mut scopes = Vec::new();
    let mut verbose = false;
    while index < bytes.len() {
        let tail = &pattern[index..];
        if bytes[index] == b'\\' {
            let Some(&next) = bytes.get(index + 1) else {
                return Err(invalid("invalid DOMAIN-REGEX escape"));
            };
            if !in_class && tail.starts_with("\\k'") {
                let rest = &tail[3..];
                let end = rest
                    .find('\'')
                    .ok_or_else(|| invalid("invalid DOMAIN-REGEX capture reference"))?;
                if rest[..end].is_empty() || !rest[..end].bytes().all(|b| b.is_ascii_digit()) {
                    capture_name(&rest[..end])?;
                }
                output.push_str("\\k<");
                output.push_str(&rest[..end]);
                output.push('>');
                index += 4 + end;
                continue;
            }
            if !in_class && matches!(next, b'g' | b'K' | b'R' | b'N' | b'O' | b'h' | b'H') {
                return Err(invalid("unsupported DOMAIN-REGEX escape"));
            }
            output.push('\\');
            let next = pattern[index + 1..].chars().next().expect("byte checked");
            output.push(next);
            index += 1 + next.len_utf8();
            continue;
        }
        if in_class {
            if tail.starts_with("&&")
                || tail.starts_with("--")
                || tail.starts_with("~~")
                || bytes[index] == b'['
            {
                return Err(invalid("unsupported DOMAIN-REGEX character class syntax"));
            }
            if bytes[index] == b']' {
                in_class = false;
            }
        } else {
            if verbose && bytes[index] == b'#' {
                let end = tail.find('\n').map_or(tail.len(), |end| end + 1);
                output.push_str(&tail[..end]);
                index += end;
                continue;
            }
            if let Some(rest) = tail.strip_prefix("(?#") {
                let end = rest
                    .find(')')
                    .ok_or_else(|| invalid("invalid DOMAIN-REGEX comment"))?;
                index += end + 4;
                continue;
            }
            if bytes[index] == b'[' {
                in_class = true;
            }
            if tail.starts_with("(?P")
                || tail.starts_with("(*")
                || tail.starts_with("(?~")
                || tail.starts_with("(?|")
                || tail.starts_with("(?(")
            {
                return Err(invalid("unsupported DOMAIN-REGEX group syntax"));
            }
            if let Some(rest) = tail.strip_prefix("(?'") {
                let end = rest
                    .find('\'')
                    .ok_or_else(|| invalid("invalid DOMAIN-REGEX capture name"))?;
                capture_name(&rest[..end])?;
                output.push_str("(?<");
                output.push_str(&rest[..end]);
                output.push('>');
                depth += 1;
                scopes.push(verbose);
                if depth > AST_DEPTH {
                    return Err(invalid("DOMAIN-REGEX compilation budget exceeded"));
                }
                index += end + 4;
                continue;
            }
            if tail.starts_with("(?<") && !tail.starts_with("(?<=") && !tail.starts_with("(?<!") {
                let rest = &tail[3..];
                let end = rest
                    .find('>')
                    .ok_or_else(|| invalid("invalid DOMAIN-REGEX capture name"))?;
                capture_name(&rest[..end])?;
            }
            if matches!(bytes[index], b'*' | b'+' | b'?' | b'}')
                && bytes.get(index + 1) == Some(&b'+')
            {
                return Err(invalid("unsupported DOMAIN-REGEX possessive quantifier"));
            }
            if bytes[index] == b'(' {
                // Account lexical depth before calling a recursive third-party parser.
                // Explicit common flags are accepted; Rust-only modes are rejected.
                if let Some(rest) = tail.strip_prefix("(?") {
                    let flags = rest
                        .bytes()
                        .take_while(|b| b.is_ascii_alphabetic() || *b == b'-')
                        .count();
                    if flags > 0
                        && tail
                            .as_bytes()
                            .get(2 + flags)
                            .is_some_and(|b| matches!(b, b':' | b')'))
                    {
                        let mut on = true;
                        let old_verbose = verbose;
                        for flag in tail[2..2 + flags].bytes() {
                            match flag {
                                b'-' => on = false,
                                b'i' | b'm' | b's' => {}
                                b'x' => verbose = on,
                                _ => return Err(invalid("unsupported DOMAIN-REGEX inline mode")),
                            }
                        }
                        if bytes[index + 2 + flags] == b')' {
                            output.push_str(&tail[..3 + flags]);
                            index += 3 + flags;
                            continue;
                        }
                        depth += 1;
                        scopes.push(old_verbose);
                        if depth > AST_DEPTH {
                            return Err(invalid("DOMAIN-REGEX compilation budget exceeded"));
                        }
                        output.push_str(&tail[..3 + flags]);
                        index += 3 + flags;
                        continue;
                    }
                }
                depth += 1;
                scopes.push(verbose);
                if depth > AST_DEPTH {
                    return Err(invalid("DOMAIN-REGEX compilation budget exceeded"));
                }
            } else if bytes[index] == b')' {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| invalid("invalid DOMAIN-REGEX group syntax"))?;
                verbose = scopes
                    .pop()
                    .ok_or_else(|| invalid("invalid DOMAIN-REGEX group syntax"))?;
            }
        }
        let next = tail.chars().next().expect("within input");
        output.push(next);
        index += next.len_utf8();
    }
    if in_class || depth != 0 {
        return Err(invalid("invalid DOMAIN-REGEX syntax"));
    }
    Ok(output)
}
fn capture_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(invalid("unsupported DOMAIN-REGEX capture name"));
    }
    Ok(())
}

/// Return a bounded .NET-number -> engine-number map, rewriting numeric
/// backreferences only. Both engines otherwise keep their original grammar.
/// `pattern` has already passed common_dialect's lexical/depth fence.
pub(super) fn capture_dialect(pattern: &str) -> Result<(String, Vec<usize>)> {
    let bytes = pattern.as_bytes();
    let mut groups = Vec::<Option<String>>::new();
    let mut references = Vec::new();
    let mut scopes = Vec::new();
    let (mut index, mut in_class, mut verbose) = (0, false, false);
    while index < bytes.len() {
        let tail = &pattern[index..];
        if bytes[index] == b'\\' {
            let next = *bytes
                .get(index + 1)
                .ok_or_else(|| invalid("invalid regex escape"))?;
            if !in_class && matches!(next, b'1'..=b'9') {
                let end = index
                    + 1
                    + bytes[index + 1..]
                        .iter()
                        .take_while(|b| b.is_ascii_digit())
                        .count();
                let number = pattern[index + 1..end]
                    .parse::<usize>()
                    .map_err(|_| invalid("invalid regex capture reference"))?;
                references.push((index, end, number));
                index = end;
                continue;
            }
            if !in_class && tail.starts_with("\\k<") {
                let end = index
                    + 3
                    + tail[3..]
                        .find('>')
                        .ok_or_else(|| invalid("invalid regex capture reference"))?;
                let key = &pattern[index + 3..end];
                if !key.is_empty() && key.bytes().all(|b| b.is_ascii_digit()) {
                    let number = key
                        .parse::<usize>()
                        .map_err(|_| invalid("invalid regex capture reference"))?;
                    references.push((index, end + 1, number));
                }
                index = end + 1;
                continue;
            }
            index += 1 + tail[1..].chars().next().expect("escape checked").len_utf8();
            continue;
        }
        if in_class {
            if bytes[index] == b']' {
                in_class = false;
            }
        } else if verbose && bytes[index] == b'#' {
            index += tail.find('\n').map_or(tail.len(), |end| end + 1);
            continue;
        } else if bytes[index] == b'[' {
            in_class = true;
        } else if bytes[index] == b'(' {
            if let Some(rest) = tail.strip_prefix("(?") {
                let flags = rest
                    .bytes()
                    .take_while(|b| b.is_ascii_alphabetic() || *b == b'-')
                    .count();
                if flags > 0
                    && bytes
                        .get(index + 2 + flags)
                        .is_some_and(|b| matches!(b, b':' | b')'))
                {
                    let old_verbose = verbose;
                    let mut on = true;
                    for flag in tail[2..2 + flags].bytes() {
                        if flag == b'-' {
                            on = false;
                        }
                        if flag == b'x' {
                            verbose = on;
                        }
                    }
                    if bytes[index + 2 + flags] == b':' {
                        scopes.push(old_verbose);
                    }
                    index += 3 + flags;
                    continue;
                }
            }
            scopes.push(verbose);
            if tail.starts_with("(?<") && !tail.starts_with("(?<=") && !tail.starts_with("(?<!") {
                let end = index
                    + 3
                    + tail[3..]
                        .find('>')
                        .ok_or_else(|| invalid("invalid regex capture name"))?;
                let name = &pattern[index + 3..end];
                // Duplicate .NET names share a capture history; neither engine's
                // ordinary single-slot name lookup can represent that history.
                if groups.iter().any(|group| group.as_deref() == Some(name)) {
                    return Err(invalid("duplicate regex capture names are unsupported"));
                }
                groups.push(Some(name.to_owned()));
                index = end + 1;
                if groups.len() > AST_NODES {
                    return Err(invalid("regex capture budget exceeded"));
                }
                continue;
            }
            if !tail.starts_with("(?") {
                groups.push(None);
                if groups.len() > AST_NODES {
                    return Err(invalid("regex capture budget exceeded"));
                }
            }
        } else if bytes[index] == b')' {
            verbose = scopes
                .pop()
                .ok_or_else(|| invalid("invalid regex group syntax"))?;
        }
        index += tail.chars().next().expect("within pattern").len_utf8();
    }
    let mut numbers = Vec::with_capacity(groups.len() + 1);
    numbers.push(0);
    for named in [false, true] {
        for (index, group) in groups.iter().enumerate() {
            if group.is_some() == named {
                numbers.push(index + 1);
            }
        }
    }
    let mut rewritten = String::with_capacity(pattern.len());
    let mut offset = 0;
    for (start, end, reference) in references {
        rewritten.push_str(&pattern[offset..start]);
        if let Some(&engine_number) = numbers
            .get(reference)
            .filter(|&&number| number != reference)
        {
            use std::fmt::Write as _;
            write!(&mut rewritten, "\\k<{engine_number}>").expect("String write");
        } else {
            // Unknown references remain the engine's compile error, rather than
            // becoming a different group or an implicit compatibility fallback.
            rewritten.push_str(&pattern[start..end]);
        }
        offset = end;
    }
    rewritten.push_str(&pattern[offset..]);
    Ok((rewritten, numbers))
}

fn inspect(root: &fancy_regex::Expr) -> Result<(usize, u64, usize)> {
    use fancy_regex::{AstNode, Expr};
    let mut pending = vec![(root, 0)];
    let (mut nodes, mut weight, mut groups) = (0_usize, 0_u64, 0_usize);
    while let Some((expr, depth)) = pending.pop() {
        nodes += 1;
        if nodes > AST_NODES || depth > AST_DEPTH {
            return Err(invalid("DOMAIN-REGEX compilation budget exceeded"));
        }
        weight = weight.saturating_add(match expr {
            Expr::Literal { val, .. } => val.len().max(1) as u64,
            Expr::Repeat { lo, hi, .. } => {
                if *lo > REPEAT_BOUND || (*hi != usize::MAX && *hi > REPEAT_BOUND) {
                    return Err(invalid("DOMAIN-REGEX compilation budget exceeded"));
                }
                (*lo)
                    .max(if *hi == usize::MAX { DOMAIN_BYTES } else { *hi })
                    .max(1) as u64
            }
            _ => 1,
        });
        match expr {
            Expr::Empty
            | Expr::Any { .. }
            | Expr::Assertion(_)
            | Expr::Literal { .. }
            | Expr::Concat(_)
            | Expr::Alt(_)
            | Expr::LookAround(..)
            | Expr::Repeat { .. }
            | Expr::Delegate { .. }
            | Expr::Backref { .. }
            | Expr::AtomicGroup(_) => {}
            Expr::Group(_) | Expr::AstNode(AstNode::AstGroup { .. }, _) => {
                groups += 1;
            }
            Expr::AstNode(
                AstNode::Backref {
                    relative_recursion_level: None,
                    ..
                },
                _,
            ) => {}
            _ => return Err(invalid("unsupported DOMAIN-REGEX expression syntax")),
        }
        pending.extend(expr.children_iter().map(|child| (child, depth + 1)));
    }
    Ok((nodes, weight.max(1), groups))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn common_domain_expressions_compile_once_and_match() {
        for (pattern, domain) in [
            (r"^(?!internal\.)[a-z0-9.-]+(?=\.test$)", "Api.Example.TEST"),
            (r"(?<=edge\.)[a-z]+(?<!private)\.test$", "edge.public.test"),
            (r"^([a-z]+)\.\1\.test$", "repeat.REPEAT.test"),
            (r"^(?<label>[a-z]+)\.\k<label>\.test$", "same.SAME.test"),
            (r"^(?'label'[a-z]+)\.\k'label'\.test$", "word.WORD.test"),
            (r"^(?#independent fixture)(?>api|www)\.test$", "API.test"),
            (
                r"^(?<label>[a-z]+)\.([a-z]+)\.\1\.\2\.test$",
                "named.part.PART.NAMED.test",
            ),
            (
                r"^(?'label'[a-z]+)\.([a-z]+)\.\k'1'\.\k'2'\.test$",
                "named.part.PART.NAMED.test",
            ),
        ] {
            let regex = DomainRegex::new(pattern).unwrap();
            assert!(
                regex
                    .match_bounded(domain, &mut DecisionBudget::new(), None)
                    .unwrap()
            );
            assert_eq!(regex, regex.clone());
            assert_eq!(format!("{regex:?}"), "DomainRegex { .. }");
        }
        assert!(
            DomainRegex::new("")
                .unwrap()
                .is_match("api.test", &Default::default())
                .unwrap()
        );
        let fast = DomainRegex::new(r"(?i)^cdn[0-9]+\.test$").unwrap();
        assert!(matches!(fast.0.engine, Engine::Linear(_)));
        assert!(
            fast.match_bounded("CDN7.test", &mut DecisionBudget::new(), None)
                .unwrap()
        );
        assert!(
            !fast
                .match_bounded("other.test", &mut DecisionBudget::new(), None)
                .unwrap()
        );
    }
    #[test]
    fn domain_decision_budget_is_shared_sticky_and_cancelled() {
        let regex = DomainRegex::new(r"(?=api)api\.test$").unwrap();
        let mut budget = DecisionBudget::new();
        budget.backtracks = 2 * (CALL_BACKTRACKS + 1);
        assert!(regex.match_bounded("api.test", &mut budget, None).unwrap());
        assert!(regex.match_bounded("api.test", &mut budget, None).unwrap());
        assert_eq!(
            regex.match_bounded("api.test", &mut budget, None),
            Err(MatchFailure::Budget)
        );
        assert_eq!(
            DomainRegex::new("test")
                .unwrap()
                .match_bounded("api.test", &mut budget, None),
            Err(MatchFailure::Budget)
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            regex.match_bounded("api.test", &mut DecisionBudget::new(), Some(&cancel)),
            Err(MatchFailure::Cancelled)
        );
        let shared = RuleDecision::default();
        shared.set_cancellation(cancel.clone());
        assert_eq!(
            regex.is_match("api.test", &shared.clone()),
            Err(MatchFailure::Cancelled)
        );
        let pathological = DomainRegex::new(r"^(a|aa)+(?=z)$").unwrap();
        assert!(
            pathological
                .match_bounded(&"a".repeat(50), &mut DecisionBudget::new(), None)
                .is_err()
        );
    }
}
