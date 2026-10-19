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

    /// The caller owns the input and output workspace permits. Allocation is
    /// checked before every append, including unmatched portions and captures.
    pub(crate) fn apply(&self, input: &str, limit: usize) -> io::Result<String> {
        if input.len() > limit {
            return Err(invalid());
        }
        let mut out = String::new();
        let mut end = 0;
        match &self.pattern {
            Pattern::Literal {
                search,
                replacement,
            } => {
                for (start, value) in input.match_indices(search.as_ref()) {
                    template::append(&mut out, &input[end..start], limit)?;
                    template::append(&mut out, replacement, limit)?;
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
                    template::append(&mut out, &input[end..found.start()], limit)?;
                    replacement.append(&captures, &mut out, limit)?;
                    end = found.end();
                    if self.occurrences == Occurrences::First {
                        break;
                    }
                }
            }
        }
        template::append(&mut out, &input[end..], limit)?;
        Ok(out)
    }
}
