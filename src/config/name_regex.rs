//! Bounded expressions for provider/group node names only.
use super::{Result, VoleError};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const PATTERN_BYTES: usize = 4096;
const NAME_BYTES: usize = 4096;
const OUTPUT_BYTES: usize = 64 * 1024;
const BACKTRACKS: usize = 10_000;

fn error(message: &'static str) -> VoleError {
    VoleError::InvalidConfig(message.into())
}
pub(super) struct Budget<'a> {
    cancel: Option<&'a CancellationToken>,
    elapsed: Duration,
    remaining: usize,
}
impl<'a> Budget<'a> {
    pub fn new(cancel: Option<&'a CancellationToken>) -> Self {
        Self {
            cancel,
            elapsed: Duration::ZERO,
            remaining: 10_000,
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.cancel.is_some_and(CancellationToken::is_cancelled) {
            return Err(error("provider expression cancelled"));
        }
        Ok(())
    }
    fn account(&mut self, elapsed: Duration) -> Result<()> {
        self.elapsed = self.elapsed.saturating_add(elapsed);
        if self.elapsed >= Duration::from_millis(100) {
            return Err(error("provider expression execution budget exceeded"));
        }
        self.check()
    }
    fn spend(&mut self, name: &str) -> Result<()> {
        self.check()?;
        if name.len() > NAME_BYTES
            || self.remaining == 0
            || self.elapsed >= Duration::from_millis(100)
        {
            return Err(error("provider expression execution budget exceeded"));
        }
        self.remaining -= 1;
        Ok(())
    }
}

pub(super) enum NameRegex {
    Fast(regex::Regex),
    Complex(Box<fancy_regex::Regex>),
}
impl NameRegex {
    pub fn new(pattern: &str) -> Result<Self> {
        if let Ok(regex) = regex::Regex::new(pattern) {
            return Ok(Self::Fast(regex));
        }
        if pattern.len() > PATTERN_BYTES {
            return Err(error("provider expression compilation budget exceeded"));
        }
        let tree = fancy_regex::Expr::parse_tree(pattern)
            .map_err(|_| error("invalid provider/group expression"))?;
        let mut pending = vec![(&tree.expr, 0)];
        let mut count = 0;
        while let Some((expr, depth)) = pending.pop() {
            count += 1;
            if count > 512 || depth > 32 {
                return Err(error("provider expression compilation budget exceeded"));
            }
            use fancy_regex::Expr;
            match expr {
                Expr::Repeat { lo, hi, .. } if *lo > 4096 || (*hi != usize::MAX && *hi > 4096) => {
                    return Err(error("provider expression compilation budget exceeded"));
                }
                Expr::Empty
                | Expr::Any { .. }
                | Expr::Assertion(_)
                | Expr::Literal { .. }
                | Expr::Concat(_)
                | Expr::Alt(_)
                | Expr::Group(_)
                | Expr::LookAround(..)
                | Expr::Repeat { .. }
                | Expr::Delegate { .. }
                | Expr::Backref { .. }
                | Expr::AtomicGroup(_) => {}
                _ => return Err(error("unsupported provider expression syntax")),
            }
            pending.extend(expr.children_iter().map(|child| (child, depth + 1)));
        }
        let regex = fancy_regex::RegexBuilder::new(pattern)
            .backtrack_limit(BACKTRACKS)
            .seek(false)
            .delegate_size_limit(512 * 1024)
            .delegate_dfa_size_limit(512 * 1024)
            .build()
            .map_err(|_| error("invalid provider/group expression"))?;
        Ok(Self::Complex(Box::new(regex)))
    }
    pub fn is_match(&self, name: &str, budget: &mut Budget<'_>) -> Result<bool> {
        budget.check()?;
        match self {
            Self::Fast(regex) => Ok(regex.is_match(name)),
            Self::Complex(regex) => {
                budget.spend(name)?;
                let started = Instant::now();
                let result = regex
                    .is_match(name)
                    .map_err(|_| error("provider expression execution budget exceeded"));
                budget.account(started.elapsed())?;
                result
            }
        }
    }
    pub fn replace(&self, name: &str, target: &str, budget: &mut Budget<'_>) -> Result<String> {
        budget.check()?;
        let started = Instant::now();
        let result = self.replace_inner(name, target, budget);
        budget.account(started.elapsed())?;
        result
    }
    fn replace_inner(&self, name: &str, target: &str, budget: &mut Budget<'_>) -> Result<String> {
        let mut output = String::new();
        let mut end = 0;
        match self {
            Self::Fast(regex) => {
                for captures in regex.captures_iter(name) {
                    budget.spend(name)?;
                    let matched = captures.get(0).expect("whole match");
                    append(&mut output, &name[end..matched.start()])?;
                    expand(
                        &mut output,
                        target,
                        name,
                        matched.start(),
                        matched.end(),
                        captures.len(),
                        |i| captures.get(i).map(|m| m.as_str()),
                        |key| {
                            regex
                                .capture_names()
                                .any(|n| n == Some(key))
                                .then(|| captures.name(key).map(|m| m.as_str()).unwrap_or(""))
                        },
                    )?;
                    end = matched.end();
                }
            }
            Self::Complex(regex) => {
                budget.spend(name)?;
                for captures in regex.captures_iter(name) {
                    budget.spend(name)?;
                    let captures = captures
                        .map_err(|_| error("provider expression execution budget exceeded"))?;
                    let matched = captures.get(0).expect("whole match");
                    append(&mut output, &name[end..matched.start()])?;
                    expand(
                        &mut output,
                        target,
                        name,
                        matched.start(),
                        matched.end(),
                        captures.len(),
                        |i| captures.get(i).map(|m| m.as_str()),
                        |key| {
                            regex
                                .capture_names()
                                .any(|n| n == Some(key))
                                .then(|| captures.name(key).map(|m| m.as_str()).unwrap_or(""))
                        },
                    )?;
                    end = matched.end();
                }
            }
        }
        append(&mut output, &name[end..])?;
        Ok(output)
    }
}
fn append(output: &mut String, value: &str) -> Result<()> {
    if output
        .len()
        .checked_add(value.len())
        .is_none_or(|n| n > OUTPUT_BYTES)
    {
        return Err(error("provider name replacement output budget exceeded"));
    }
    output.push_str(value);
    Ok(())
}
// The reference uses .NET replacement syntax: numeric captures stop at a non-digit.
#[allow(clippy::too_many_arguments)]
fn expand<'a>(
    output: &mut String,
    target: &str,
    input: &'a str,
    start: usize,
    end: usize,
    count: usize,
    group: impl Fn(usize) -> Option<&'a str>,
    named: impl Fn(&str) -> Option<&'a str>,
) -> Result<()> {
    let mut rest = target;
    while let Some(index) = rest.find('$') {
        append(output, &rest[..index])?;
        rest = &rest[index..];
        let next = rest.as_bytes().get(1).copied();
        let (consumed, value) = match next {
            Some(b'$') => (2, Some("$")),
            Some(b'&') => (2, group(0)),
            Some(b'`') => (2, Some(&input[..start])),
            Some(b'\'') => (2, Some(&input[end..])),
            Some(b'_') => (2, Some(input)),
            Some(b'+') => (2, (1..count).rev().find_map(&group).or(Some(""))),
            Some(b'{') => {
                if let Some(close) = rest.find('}') {
                    let key = &rest[2..close];
                    let value = key
                        .parse::<usize>()
                        .ok()
                        .filter(|i| *i < count)
                        .map(|i| group(i).unwrap_or(""))
                        .or_else(|| named(key));
                    (close + 1, value)
                } else {
                    (1, None)
                }
            }
            Some(b'0'..=b'9') => {
                let length = 1 + rest[1..].bytes().take_while(u8::is_ascii_digit).count();
                let value = rest[1..length]
                    .parse::<usize>()
                    .ok()
                    .filter(|i| *i < count)
                    .map(|i| group(i).unwrap_or(""));
                (length, value)
            }
            _ => (1, None),
        };
        append(output, value.unwrap_or(&rest[..consumed]))?;
        rest = &rest[consumed..];
    }
    append(output, rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn name_expressions_support_real_subscription_patterns() {
        let mut budget = Budget::new(None);
        let exclude = NameRegex::new(r"^(?!.*(流量|到期)).*(香港|HK)").unwrap();
        assert!(exclude.is_match("香港 HK-01", &mut budget).unwrap());
        assert!(!exclude.is_match("香港 剩余流量", &mut budget).unwrap());
        let repeated = NameRegex::new(r"^(HK|SG)-\1$").unwrap();
        assert!(repeated.is_match("HK-HK", &mut budget).unwrap());
        assert!(!repeated.is_match("HK-SG", &mut budget).unwrap());
        let rename = NameRegex::new(r"(?<=HK-)(\d+)").unwrap();
        assert_eq!(
            rename.replace("HK-01", "$1x", &mut budget).unwrap(),
            "HK-01x"
        );
        let fast = NameRegex::new(r"(?<area>HK)-(\d+)").unwrap();
        assert_eq!(
            fast.replace("HK-01", "${area}:$2x:$$:$&", &mut budget)
                .unwrap(),
            "HK:01x:$:HK-01"
        );
    }
    #[test]
    fn name_expressions_fail_on_budget_and_cancellation() {
        let regex = NameRegex::new(r"(?i)(a|b|ab)*(?>c)").unwrap();
        assert!(
            regex
                .is_match(&"ab".repeat(40), &mut Budget::new(None))
                .is_err()
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            NameRegex::new("HK")
                .unwrap()
                .is_match("HK", &mut Budget::new(Some(&cancel)))
                .is_err()
        );
        assert!(NameRegex::new(r"(?=a)a{1000000}").is_err());
    }
}
