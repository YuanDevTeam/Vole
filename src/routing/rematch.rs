//! Sparse generation-owned controls and decision-local bounded cycle tracking.
use std::sync::Arc;

use crate::config::{
    MatchFailure, ProxyConfig, ProxyId, ProxyProtocol, RematchConfig, RuleDecision,
};

pub(crate) struct RematchTarget {
    pub(super) name: Arc<str>,
    pub(super) config: RematchConfig,
}

/// The ordinary graph keeps None; only actual rematch nodes allocate entries.
#[derive(Clone, Default)]
pub(crate) struct RematchTargets(Option<Arc<[(ProxyId, Arc<RematchTarget>)]>>);
impl RematchTargets {
    pub(crate) fn new(proxies: &[ProxyConfig]) -> Self {
        let mut entries = Vec::new();
        for (index, proxy) in proxies.iter().enumerate() {
            if let ProxyProtocol::Rematch(config) = &proxy.protocol {
                entries.push((
                    ProxyId::new(index).expect("proxy index"),
                    Arc::new(RematchTarget {
                        name: Arc::from(proxy.tag.as_str()),
                        config: config.clone(),
                    }),
                ));
            }
        }
        Self((!entries.is_empty()).then(|| Arc::from(entries)))
    }
    pub(super) fn get(&self, id: ProxyId) -> Option<&Arc<RematchTarget>> {
        let entries = self.0.as_ref()?;
        entries
            .binary_search_by_key(&id.index(), |(index, _)| index.index())
            .ok()
            .map(|index| &entries[index].1)
    }
}

/// Allocated once, only when a decision first encounters a rematch target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RematchCursor {
    visited: [Option<Arc<str>>; 32],
    count: usize,
    pub(super) unlisted_index: usize,
}
impl RematchCursor {
    pub(super) fn new(unlisted_index: usize) -> Self {
        Self {
            visited: std::array::from_fn(|_| None),
            count: 0,
            unlisted_index,
        }
    }
    pub(super) fn enter(
        &mut self,
        name: &Arc<str>,
        decision: &RuleDecision,
    ) -> Result<(), MatchFailure> {
        decision.check()?;
        if self.count == self.visited.len()
            || self.visited[..self.count]
                .iter()
                .any(|old| old.as_deref() == Some(name.as_ref()))
        {
            return Err(MatchFailure::Budget);
        }
        self.visited[self.count] = Some(name.clone());
        self.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reentry_is_bounded_by_node_identity_and_keeps_shared_names() {
        let mut cursor = RematchCursor::new(9);
        let decision = RuleDecision::default();
        let first: Arc<str> = Arc::from("first");
        cursor.enter(&first, &decision).unwrap();
        assert!(Arc::ptr_eq(cursor.visited[0].as_ref().unwrap(), &first));
        assert_eq!(
            cursor.enter(&Arc::from("first"), &decision),
            Err(MatchFailure::Budget)
        );
        for index in 1..32 {
            cursor
                .enter(&Arc::from(format!("node-{index}")), &decision)
                .unwrap();
        }
        assert_eq!(
            cursor.enter(&Arc::from("next"), &decision),
            Err(MatchFailure::Budget)
        );
    }
}
