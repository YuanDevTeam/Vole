//! Immutable byte-trie representation of the public MRSv1 domain format.
//!
//! Each node contributes its child edges as zero bits followed by a one bit
//! (LOUDS). Edge labels and terminal bits stay contiguous; a sparse directory
//! records every 32nd node's bit offset. Queries borrow the normalized domain
//! and never construct a reversed string or a heap-backed traversal stack.
use super::{Result, corrupt};
use std::ops::Range;

const DIRECTORY_STRIDE: usize = 32;
const MAX_MRS_DEPTH: usize = 253;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct DomainSet {
    leaves: Box<[u64]>,
    bitmap: Box<[u64]>,
    labels: Box<[u8]>,
    directory: Box<[u32]>,
    ordered: bool,
}

impl DomainSet {
    pub(super) fn from_patterns(patterns: Vec<String>) -> Result<Self> {
        let mut keys = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            if let Some(domain) = pattern.strip_prefix("+.") {
                let mut suffix = domain.as_bytes().to_vec();
                suffix.reverse();
                keys.push(suffix.clone());
                suffix.push(b'.');
                keys.push(suffix);
            } else {
                let mut key = pattern.into_bytes();
                key.reverse();
                keys.push(key);
            }
        }
        keys.sort_unstable();
        keys.dedup();
        if keys.is_empty() {
            return Ok(Self::default());
        }

        let mut leaves = Vec::new();
        let mut bitmap = Vec::new();
        let mut labels = Vec::new();
        let mut directory = Vec::new();
        let mut layer = std::iter::once(0..keys.len()).collect::<Vec<_>>();
        let mut next = Vec::new();
        let (mut node, mut bit, mut depth) = (0, 0, 0);
        while !layer.is_empty() {
            for mut group in layer.drain(..) {
                if node % DIRECTORY_STRIDE == 0 {
                    directory.push(u32::try_from(bit).map_err(|_| corrupt())?);
                }
                if keys[group.start].len() == depth {
                    set_bit(&mut leaves, node);
                    group.start += 1;
                }
                while group.start < group.end {
                    let start = group.start;
                    let label = keys[start][depth];
                    group.start += 1;
                    while group.start < group.end && keys[group.start][depth] == label {
                        group.start += 1;
                    }
                    labels.push(label);
                    next.push(start..group.start);
                    bit += 1;
                }
                set_bit(&mut bitmap, bit);
                bit += 1;
                node += 1;
            }
            std::mem::swap(&mut layer, &mut next);
            depth += 1;
        }
        // Nonterminal nodes at the end still need a terminal bitmap slot.
        leaves.resize(node.div_ceil(64), 0);
        Ok(Self {
            leaves: leaves.into_boxed_slice(),
            bitmap: bitmap.into_boxed_slice(),
            labels: labels.into_boxed_slice(),
            directory: directory.into_boxed_slice(),
            ordered: true,
        })
    }

    pub(super) fn from_mrs(
        mut leaves: Vec<u64>,
        mut bitmap: Vec<u64>,
        labels: Vec<u8>,
    ) -> Result<Self> {
        let nodes = labels.len().checked_add(1).ok_or_else(corrupt)?;
        if leaves.len().saturating_mul(64) < nodes {
            return Err(corrupt());
        }
        let mut directory = Vec::with_capacity(nodes.div_ceil(DIRECTORY_STRIDE));
        let (mut position, mut edge) = (0, 0);
        let (mut ordered, mut duplicate) = (true, false);
        for node in 0..nodes {
            if node % DIRECTORY_STRIDE == 0 {
                directory.push(u32::try_from(position).map_err(|_| corrupt())?);
            }
            let start = edge;
            while position < bitmap.len().saturating_mul(64) && !bit(&bitmap, position) {
                edge += 1;
                // Child IDs are edge + 1; every child follows its parent.
                if edge <= node || edge >= nodes {
                    return Err(corrupt());
                }
                position += 1;
            }
            if position >= bitmap.len().saturating_mul(64) {
                return Err(corrupt());
            }
            ordered &= labels[start..edge].windows(2).all(|pair| pair[0] < pair[1]);
            let mut seen = [0_u64; 4];
            for label in &labels[start..edge] {
                let (word, mask) = (usize::from(*label / 64), 1_u64 << (*label % 64));
                duplicate |= seen[word] & mask != 0;
                seen[word] |= mask;
            }
            position += 1;
        }
        if edge != labels.len() {
            return Err(corrupt());
        }
        // Padding was ignored by the previous decoder; discard it rather than
        // retaining attacker-controlled extra bitmap words in a generation.
        leaves.truncate(nodes.div_ceil(64));
        bitmap.truncate(position.div_ceil(64));
        let mut set = Self {
            leaves: leaves.into_boxed_slice(),
            bitmap: bitmap.into_boxed_slice(),
            labels: labels.into_boxed_slice(),
            directory: directory.into_boxed_slice(),
            ordered,
        };
        // Older decoders merged duplicate character branches when constructing
        // the domain index. Retain that union for noncanonical inputs without
        // imposing a repeated-branch search cost on every ordinary query.
        let mut patterns = duplicate.then(Vec::new);
        set.validate_paths(patterns.as_mut())?;
        match patterns {
            Some(patterns) => Self::from_patterns(patterns),
            None => Ok(set),
        }
    }

    // Validate every path once without expanding terminal domains. Previous MRS
    // decoding removed terminal '+' bytes before interpreting domain patterns;
    // moving those terminal bits to their ancestor preserves that behavior.
    fn validate_paths(&mut self, mut patterns: Option<&mut Vec<String>>) -> Result<()> {
        let mut path = [0_u8; MAX_MRS_DEPTH];
        let mut frames: [Range<usize>; MAX_MRS_DEPTH + 1] = std::array::from_fn(|_| 0..0);
        let mut ancestors = [0_usize; MAX_MRS_DEPTH + 1];
        frames[0] = self.children(0);
        let mut depth = 0;
        loop {
            let Some(edge) = frames[depth].next() else {
                if depth == 0 {
                    return Ok(());
                }
                depth -= 1;
                continue;
            };
            if depth == MAX_MRS_DEPTH {
                return Err(corrupt());
            }
            path[depth] = self.labels[edge];
            depth += 1;
            let node = edge + 1;
            ancestors[depth] = node;
            if self.terminal(node) {
                let key = std::str::from_utf8(&path[..depth]).map_err(|_| corrupt())?;
                if let Some(patterns) = patterns.as_deref_mut() {
                    patterns.push(key.trim_end_matches('+').chars().rev().collect());
                }
                let mut terminal_depth = depth;
                while terminal_depth > 0 && path[terminal_depth - 1] == b'+' {
                    terminal_depth -= 1;
                }
                if terminal_depth != depth {
                    self.leaves[node / 64] &= !(1_u64 << (node % 64));
                    let terminal = ancestors[terminal_depth];
                    self.leaves[terminal / 64] |= 1_u64 << (terminal % 64);
                }
            }
            frames[depth] = self.children(node);
        }
    }

    pub(super) fn contains(&self, name: &str) -> bool {
        !name.is_empty()
            && name.len() <= MAX_MRS_DEPTH
            && !self.labels.is_empty()
            && self.matches_label(0, name, false)
    }

    fn matches_label(&self, node: usize, name: &str, suffix: bool) -> bool {
        if name.is_empty() {
            return self.terminal(node);
        }
        if suffix && self.terminal(node) {
            return true;
        }
        let (rest, label) = name.rsplit_once('.').unwrap_or(("", name));
        let mut literal = Some(node);
        for byte in label.bytes().rev() {
            literal = literal.and_then(|current| self.child(current, byte));
            if literal.is_none() {
                break;
            }
        }
        literal.is_some_and(|end| self.finish_label(end, rest))
            || self
                .child(node, b'*')
                .is_some_and(|end| self.finish_label(end, rest))
    }

    fn finish_label(&self, node: usize, rest: &str) -> bool {
        if rest.is_empty() {
            self.terminal(node)
        } else {
            self.child(node, b'.')
                .is_some_and(|next| self.matches_label(next, rest, true))
        }
    }

    fn child(&self, node: usize, label: u8) -> Option<usize> {
        let children = self.children(node);
        let labels = &self.labels[children.clone()];
        let offset = if self.ordered {
            labels.binary_search(&label).ok()
        } else {
            labels.iter().position(|candidate| *candidate == label)
        };
        offset.map(|offset| children.start + offset + 1)
    }

    fn terminal(&self, node: usize) -> bool {
        bit(&self.leaves, node)
    }

    fn children(&self, node: usize) -> Range<usize> {
        let sample = self.directory[node / DIRECTORY_STRIDE] as usize;
        let offset = node % DIRECTORY_STRIDE;
        let start = if offset == 0 {
            sample
        } else {
            self.select_one(sample, offset - 1) + 1
        };
        let end = self.select_one(start, 0);
        start - node..end - node
    }

    fn select_one(&self, start: usize, mut rank: usize) -> usize {
        let mut index = start / 64;
        let mut word = self.bitmap[index] & (u64::MAX << (start % 64));
        loop {
            let count = word.count_ones() as usize;
            if rank < count {
                return index * 64 + nth_one(word, rank);
            }
            rank -= count;
            index += 1;
            word = self.bitmap[index];
        }
    }
}

fn bit(words: &[u64], offset: usize) -> bool {
    words
        .get(offset / 64)
        .is_some_and(|word| word & (1_u64 << (offset % 64)) != 0)
}

fn set_bit(words: &mut Vec<u64>, offset: usize) {
    words.resize(words.len().max(offset / 64 + 1), 0);
    words[offset / 64] |= 1_u64 << (offset % 64);
}

fn nth_one(mut word: u64, mut rank: usize) -> usize {
    if rank == 0 {
        return word.trailing_zeros() as usize;
    }
    let mut offset = 0;
    for width in [32, 16, 8, 4, 2, 1] {
        let count = (word & ((1_u64 << width) - 1)).count_ones() as usize;
        if rank >= count {
            rank -= count;
            word >>= width;
            offset += width;
        }
    }
    offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::policy::DomainIndex;

    fn chain(key: &[u8], terminals: &[usize]) -> Result<DomainSet> {
        let mut leaves = vec![0; (key.len() + 1).div_ceil(64)];
        for terminal in terminals {
            set_bit(&mut leaves, *terminal);
        }
        let mut bitmap = Vec::new();
        for index in 0..key.len() {
            set_bit(&mut bitmap, index * 2 + 1);
        }
        set_bit(&mut bitmap, key.len() * 2);
        DomainSet::from_mrs(leaves, bitmap, key.to_vec())
    }

    #[test]
    fn compact_domains_match_existing_label_index_including_overlapping_wildcards() {
        let mut groups = vec![
            vec!["example.com"],
            vec![".example.com"],
            vec!["+.example.com"],
            vec!["*.example.com"],
            vec!["*.a.*.example.com"],
            vec!["deep.api.example.com", "*.example.com"],
            vec!["dead.api.example.com", "api.*.com"],
            vec!["deep.api.example.com", ".example.com"],
            vec!["*.api.example.com", ".api.example.com", "api.example.com"],
            vec!["example.com", "example.com", ".example.com"],
            vec!["xn--xample-9ua.test", "é.test"],
        ];
        let generated = ["a", "b", "*"]
            .into_iter()
            .flat_map(|a| {
                ["a", "b", "*"].into_iter().flat_map(move |b| {
                    [
                        format!("{a}.{b}"),
                        format!(".{a}.{b}"),
                        format!("+.{a}.{b}"),
                    ]
                })
            })
            .collect::<Vec<_>>();
        groups.extend(generated.iter().map(|pattern| vec![pattern.as_str()]));
        let mut queries = vec![
            "example.com".to_owned(),
            "api.example.com".to_owned(),
            "www.api.example.com".to_owned(),
            "www.a.api.example.com".to_owned(),
            "deep.api.example.com".to_owned(),
            "api.other.com".to_owned(),
            "fooexample.com".to_owned(),
            "xn--xample-9ua.test".to_owned(),
            "xn--9ca.test".to_owned(),
        ];
        for a in ["a", "b", "c"] {
            queries.push(a.to_owned());
            for b in ["a", "b", "c"] {
                queries.push(format!("{a}.{b}"));
                for c in ["a", "b", "c"] {
                    queries.push(format!("{a}.{b}.{c}"));
                }
            }
        }
        for patterns in groups {
            let mut old = DomainIndex::new();
            for pattern in &patterns {
                old.insert(pattern, 0);
            }
            let compact =
                DomainSet::from_patterns(patterns.iter().map(|s| (*s).into()).collect()).unwrap();
            for query in &queries {
                assert_eq!(
                    compact.contains(query),
                    old.find(0, query).is_some(),
                    "patterns {patterns:?}, query {query}"
                );
            }
        }
    }

    #[test]
    fn mrs_terminal_markers_keep_exact_suffix_and_whole_label_wildcards() {
        let suffix = chain(b"tset.+", &[6]).unwrap();
        assert!(!suffix.contains("test"));
        assert!(suffix.contains("a.test"));
        assert!(suffix.contains("a.b.test"));
        assert!(!suffix.contains("atest"));
        let both = chain(b"tset.+", &[4, 6]).unwrap();
        assert!(both.contains("test"));
        assert!(both.contains("a.test"));
        let wildcard = chain(b"tset.*", &[6]).unwrap();
        assert!(!wildcard.contains("test"));
        assert!(wildcard.contains("a.test"));
        assert!(!wildcard.contains("a.b.test"));
        let repeated_marker = chain(b"tset++", &[6]).unwrap();
        assert!(repeated_marker.contains("test"));
        assert!(!repeated_marker.contains("a.test"));
    }

    #[test]
    fn mrs_retains_noncanonical_edge_order_and_duplicate_branch_union() {
        let unordered = DomainSet::from_mrs(vec![6], vec![0b11100], b"ba".to_vec()).unwrap();
        assert!(!unordered.ordered);
        assert!(unordered.contains("a"));
        assert!(unordered.contains("b"));
        assert!(!unordered.contains("c"));
        // Root has two 'a' children, respectively followed by 'b' and 'c'.
        let duplicate = DomainSet::from_mrs(vec![24], vec![0b111010100], b"aabc".to_vec()).unwrap();
        assert!(duplicate.ordered);
        assert!(duplicate.contains("ba"));
        assert!(duplicate.contains("ca"));
        assert!(!duplicate.contains("a"));
    }

    #[test]
    fn mrs_validation_bounds_paths_utf8_and_structure_without_enumeration() {
        assert!(chain(&[b'a'; 253], &[253]).is_ok());
        assert!(chain(&[b'a'; 254], &[]).is_err());
        assert!(chain(&[0xff], &[1]).is_err());
        assert!(chain(&[0xff], &[]).is_ok());
        assert!(DomainSet::from_mrs(vec![], vec![6], vec![b'a']).is_err());
        assert!(DomainSet::from_mrs(vec![0], vec![], vec![b'a']).is_err());
        assert!(DomainSet::from_mrs(vec![0], vec![0], vec![b'a']).is_err());
        // An empty root cannot own a later node with a back-edge to itself.
        assert!(DomainSet::from_mrs(vec![0], vec![1], vec![b'a']).is_err());
        let mut padded = chain(b"a", &[1]).unwrap();
        let labels = padded.labels.to_vec();
        let mut leaves = padded.leaves.to_vec();
        let mut bitmap = padded.bitmap.to_vec();
        leaves.push(u64::MAX);
        bitmap.push(u64::MAX);
        padded = DomainSet::from_mrs(leaves, bitmap, labels).unwrap();
        assert_eq!(padded.leaves.len(), 1);
        assert_eq!(padded.bitmap.len(), 1);
        assert!(padded.contains("a"));
        assert!(!padded.contains("b"));
        let root_only = DomainSet::from_mrs(vec![1], vec![1], Vec::new()).unwrap();
        assert!(!root_only.contains("a"));
        // The MRS file's depth bound does not add a YAML/Text pattern limit.
        assert!(DomainSet::from_patterns(vec!["a".repeat(254)]).is_ok());
    }

    #[test]
    fn compact_domain_storage_is_linear_in_edges_and_has_no_per_node_allocations() {
        let patterns = (0..10_000)
            .map(|index| format!("+.host{index:05}.example"))
            .collect::<Vec<_>>();
        let source_bytes = patterns.iter().map(String::len).sum::<usize>();
        let compact = DomainSet::from_patterns(patterns).unwrap();
        let stored_bytes = compact.leaves.len() * 8
            + compact.bitmap.len() * 8
            + compact.labels.len()
            + compact.directory.len() * 4;
        assert!(stored_bytes <= compact.labels.len() * 3 / 2 + 32);
        assert!(stored_bytes < source_bytes);
        for query in ["host00000.example", "a.host09999.example"] {
            assert!(compact.contains(query));
        }
        assert!(!compact.contains("host10000.example"));
    }
}
