//! Source-local payload storage; live Bytes keep their storage until final drop.
use std::sync::{Arc, Mutex};

use bytes::Bytes;

pub(crate) struct ReceivePool {
    maximum: usize,
    free: Mutex<Vec<Vec<u8>>>,
}

impl std::fmt::Debug for ReceivePool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceivePool")
            .finish_non_exhaustive()
    }
}

impl ReceivePool {
    pub(crate) fn new(maximum: usize) -> Arc<Self> {
        Arc::new(Self {
            maximum,
            free: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn copy(self: &Arc<Self>, payload: &[u8]) -> Bytes {
        if payload.is_empty() {
            return Bytes::new();
        }
        if payload.len() > self.maximum {
            return Bytes::copy_from_slice(payload);
        }
        let mut storage = self
            .free
            .lock()
            .ok()
            .and_then(|mut free| free.pop())
            .unwrap_or_default();
        storage.clear();
        storage.reserve_exact(payload.len());
        storage.extend_from_slice(payload);
        Bytes::from_owner(Received {
            storage,
            pool: self.clone(),
        })
    }
}

struct Received {
    storage: Vec<u8>,
    pool: Arc<ReceivePool>,
}

impl AsRef<[u8]> for Received {
    fn as_ref(&self) -> &[u8] {
        &self.storage
    }
}

impl Drop for Received {
    fn drop(&mut self) {
        if self.storage.capacity() > self.pool.maximum {
            return;
        }
        if let Ok(mut free) = self.pool.free.lock()
            && free.len() < crate::limits::IO_POLL_BUDGET
        {
            let mut storage = std::mem::take(&mut self.storage);
            storage.clear();
            free.push(storage);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_pool_preserves_live_aliases_and_releases_its_owner() {
        let pool = ReceivePool::new(1500);
        let first = pool.copy(&[7; 1200]);
        let pointer = first.as_ptr();
        let alias = first.slice(100..200);
        drop(first);
        let second = pool.copy(&[9; 1200]);
        assert_ne!(second.as_ptr(), pointer);
        assert_eq!(&alias[..], &[7; 100]);
        drop(second);
        drop(alias);
        let reused = pool.copy(&[11; 1200]);
        assert_eq!(reused.as_ptr(), pointer);
        assert_eq!(&reused[..], &[11; 1200]);
        let owner = Arc::downgrade(&pool);
        drop(pool);
        assert!(owner.upgrade().is_some());
        drop(reused);
        assert!(owner.upgrade().is_none());
    }

    #[test]
    fn receive_pool_bounds_retained_storage_without_rejecting_payloads() {
        let pool = ReceivePool::new(1500);
        let live = (0..crate::limits::IO_POLL_BUDGET + 8)
            .map(|_| pool.copy(&[3; 1200]))
            .collect::<Vec<_>>();
        assert!(pool.free.lock().unwrap().is_empty());
        drop(live);
        let free = pool.free.lock().unwrap();
        assert_eq!(free.len(), crate::limits::IO_POLL_BUDGET);
        assert!(free.iter().all(|storage| storage.capacity() <= 1500));
        drop(free);
        let oversized = pool.copy(&[5; 2000]);
        assert_eq!(&oversized[..], &[5; 2000]);
        drop(oversized);
        assert_eq!(
            pool.free.lock().unwrap().len(),
            crate::limits::IO_POLL_BUDGET
        );
        assert!(pool.copy(&[]).is_empty());
    }
}
