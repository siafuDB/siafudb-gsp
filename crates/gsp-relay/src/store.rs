//! Storage behind the relay: an append-only list of opaque items per
//! fragment. Numbering, dedupe, quotas and auth live in [`crate::Relay`];
//! a store only has to keep bytes in order.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

/// BLAKE3 hash of a relay token, as persisted.
pub type TokenHash = [u8; 32];

/// What a store hands back at startup for one fragment.
#[derive(Debug, Clone)]
pub struct LoadedFragment {
    /// Fragment id.
    pub fragment_id: Vec<u8>,
    /// Registered `BLAKE3(relay_token)`.
    pub token_hash: TokenHash,
    /// For each stored item, in cursor order (first is cursor 1): its BLAKE3
    /// hash and its length in bytes.
    pub items: Vec<([u8; 32], u32)>,
}

/// Append-only item storage. Calls may block on disk I/O; the relay runs
/// them on the blocking thread pool.
///
/// The relay guarantees: `create` is called once per fragment before any
/// `append`; appends to one fragment are serialized and `first_seq` is always
/// the current item count plus one; `read` is only asked for items whose
/// `append` has returned `Ok`.
pub trait Store: Send + Sync + 'static {
    /// Called once at startup. Returns every fragment the store holds.
    fn load(&self) -> io::Result<Vec<LoadedFragment>>;

    /// Persist a new, empty fragment and its token hash.
    fn create(&self, fragment_id: &[u8], token_hash: &TokenHash) -> io::Result<()>;

    /// Append `items` as cursors `first_seq..`. All or nothing: on `Err` the
    /// fragment must be left as it was before the call.
    fn append(&self, fragment_id: &[u8], first_seq: u64, items: &[Vec<u8>]) -> io::Result<()>;

    /// Items with cursor greater than `after`, in order: at most `max_items`,
    /// stopping before the item that would push the total past `max_bytes`,
    /// but always at least one if any exists.
    fn read(
        &self,
        fragment_id: &[u8],
        after: u64,
        max_items: usize,
        max_bytes: usize,
    ) -> io::Result<Vec<Vec<u8>>>;
}

impl<S: Store> Store for std::sync::Arc<S> {
    fn load(&self) -> io::Result<Vec<LoadedFragment>> {
        (**self).load()
    }
    fn create(&self, fragment_id: &[u8], token_hash: &TokenHash) -> io::Result<()> {
        (**self).create(fragment_id, token_hash)
    }
    fn append(&self, fragment_id: &[u8], first_seq: u64, items: &[Vec<u8>]) -> io::Result<()> {
        (**self).append(fragment_id, first_seq, items)
    }
    fn read(
        &self,
        fragment_id: &[u8],
        after: u64,
        max_items: usize,
        max_bytes: usize,
    ) -> io::Result<Vec<Vec<u8>>> {
        (**self).read(fragment_id, after, max_items, max_bytes)
    }
}

/// Volatile store: everything is lost when the process exits.
#[derive(Default)]
pub struct MemStore {
    fragments: Mutex<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
}

impl MemStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every byte this store holds (fragment ids and items, concatenated).
    /// For tests that check what the relay retains.
    pub fn dump(&self) -> Vec<u8> {
        let g = lock(&self.fragments);
        let mut out = Vec::new();
        for (id, items) in g.iter() {
            out.extend_from_slice(id);
            for item in items {
                out.extend_from_slice(item);
            }
        }
        out
    }
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A poisoned lock only means another thread panicked while holding it.
    // Every critical section here leaves the data consistent before any call
    // that could panic, so keep serving.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn unknown() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "unknown fragment")
}

impl Store for MemStore {
    fn load(&self) -> io::Result<Vec<LoadedFragment>> {
        Ok(Vec::new())
    }

    fn create(&self, fragment_id: &[u8], _token_hash: &TokenHash) -> io::Result<()> {
        lock(&self.fragments)
            .entry(fragment_id.to_vec())
            .or_default();
        Ok(())
    }

    fn append(&self, fragment_id: &[u8], first_seq: u64, items: &[Vec<u8>]) -> io::Result<()> {
        let mut g = lock(&self.fragments);
        let list = g.get_mut(fragment_id).ok_or_else(unknown)?;
        if first_seq != list.len() as u64 + 1 {
            return Err(io::Error::other("append out of sequence"));
        }
        list.extend(items.iter().cloned());
        Ok(())
    }

    fn read(
        &self,
        fragment_id: &[u8],
        after: u64,
        max_items: usize,
        max_bytes: usize,
    ) -> io::Result<Vec<Vec<u8>>> {
        let g = lock(&self.fragments);
        let list = g.get(fragment_id).ok_or_else(unknown)?;
        let start = usize::try_from(after).unwrap_or(usize::MAX).min(list.len());
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for item in list[start..].iter().take(max_items) {
            if !out.is_empty() && bytes.saturating_add(item.len()) > max_bytes {
                break;
            }
            bytes = bytes.saturating_add(item.len());
            out.push(item.clone());
        }
        Ok(out)
    }
}
