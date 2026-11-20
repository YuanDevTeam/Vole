//! Text replacement shared by header and body actions.
use regex::Regex;
use std::io;

use super::{
    MAX_BODY_VALUE, MAX_PATTERN, Occurrences, SearchMode, bounded_regex, invalid, template,
};

pub(crate) struct Search {
    pattern: Pattern,
    occurrences: Occurrences,
}

enum Pattern {
    Literal {
        search: Box<str>,
        replacement: Box<str>,
    },
    Regex {
        search: Regex,
        replacement: template::Template,
    },
}

impl Search {
    pub(crate) fn compile(
        search: String,
        replacement: String,
        mode: SearchMode,
        occurrences: Occurrences,
    ) -> io::Result<Self> {
        if search.len() > MAX_PATTERN || replacement.len() > MAX_BODY_VALUE {
            return Err(invalid());
        }
        let pattern = match mode {
            SearchMode::Literal => {
                if search.is_empty() {
                    return Err(invalid());
                }
                Pattern::Literal {
                    search: search.into(),
                    replacement: replacement.into(),
                }
            }
            SearchMode::Regex => {
                let search = bounded_regex(&search)?;
                let replacement = template::Template::compile(&replacement, &search)?;
                Pattern::Regex {
                    search,
                    replacement,
                }
            }
        };
        Ok(Self {
            pattern,
            occurrences,
        })
    }

    /// Preallocate the actual body owner at a proven byte upper bound.
    /// Literal matches are nonempty and nonoverlapping, so replacing each with
    /// no more bytes cannot increase any output prefix beyond the input size.
    /// Regex/templates and potentially growing literals retain the full limit.
    pub(crate) fn output_capacity(&self, input_bytes: usize, limit: usize) -> usize {
        match &self.pattern {
            Pattern::Literal {
                search,
                replacement,
            } if replacement.len() <= search.len() => input_bytes.min(limit),
            _ => limit,
        }
    }

    /// A read-only shape proof for a separately admitted body output.
    /// Literal NUL and dollar are data; regex replacement templates stay out.
    pub(crate) fn ascii_literal_byte_map(&self) -> Option<(u8, u8, Occurrences)> {
        let Pattern::Literal {
            search,
            replacement,
        } = &self.pattern
        else {
            return None;
        };
        let [search] = search.as_bytes() else {
            return None;
        };
        let [replacement] = replacement.as_bytes() else {
            return None;
        };
        (search.is_ascii() && replacement.is_ascii()).then_some((
            *search,
            *replacement,
            self.occurrences,
        ))
    }

    /// The caller owns the input and output workspace permits. Allocation is
    /// checked before every append, including unmatched portions and captures.
    pub(crate) fn apply(&self, input: &str, limit: usize) -> io::Result<String> {
        let mut out = String::new();
        self.apply_into(input, &mut out, limit)?;
        Ok(out)
    }

    /// Reuse a caller-owned, already charged output workspace. Existing output
    /// is discarded; callers commit only after this operation succeeds.
    pub(crate) fn apply_into(&self, input: &str, out: &mut String, limit: usize) -> io::Result<()> {
        out.clear();
        if input.len() > limit {
            return Err(invalid());
        }
        let mut end = 0;
        match &self.pattern {
            Pattern::Literal {
                search,
                replacement,
            } => {
                for (start, value) in input.match_indices(search.as_ref()) {
                    template::append(out, &input[end..start], limit)?;
                    template::append(out, replacement, limit)?;
                    end = start + value.len();
                    if self.occurrences == Occurrences::First {
                        break;
                    }
                }
            }
            Pattern::Regex {
                search,
                replacement,
            } => {
                for captures in search.captures_iter(input) {
                    let found = captures.get(0).expect("regex always has capture zero");
                    template::append(out, &input[end..found.start()], limit)?;
                    replacement.append(&captures, out, limit)?;
                    end = found.end();
                    if self.occurrences == Occurrences::First {
                        break;
                    }
                }
            }
        }
        template::append(out, &input[end..], limit)
    }
}
