//! Relay core: token registration, numbering, dedupe, quotas, long-poll.
//! Transport-independent; [`crate::http`] maps it onto HTTP.

use crate::config::{Config, ITEM_OVERHEAD};
use crate::log::{frag, info, warning};
use crate::store::{Store, TokenHash, lock};
use gsp_wire::{Message, SealedOp};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

/// Longest fragment id the wire format allows.
pub const MAX_FRAGMENT_ID: usize = gsp_wire::types::MAX_FRAGMENT_ID;

/// A refused request: HTTP status plus a fixed, non-sensitive message. It is
/// sent as an `Error` frame whose `code` is the HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reject {
    /// HTTP status code.
    pub status: u16,
    /// Human-readable detail. Never contains request data.
    pub message: &'static str,
}

impl Reject {
    pub(crate) const fn new(status: u16, message: &'static str) -> Reject {
        Reject { status, message }
    }
}

const BAD_TOKEN: Reject = Reject::new(401, "relay token rejected for this fragment");
const STORAGE: Reject = Reject::new(500, "storage error");

struct FragState {
    /// The store has this fragment (its token hash is durable).
    created: bool,
    /// Cursor of the last stored item.
    head: u64,
    /// Bytes charged against the fragment quota.
    bytes: u64,
    /// BLAKE3 of every stored item, for byte-identical dedupe.
    seen: HashSet<[u8; 32]>,
}

struct Frag {
    token_hash: TokenHash,
    state: Mutex<FragState>,
}

#[derive(Default)]
struct Polls {
    total: usize,
    per: HashMap<Vec<u8>, (watch::Sender<()>, usize)>,
}

struct Inner {
    cfg: Config,
    store: Box<dyn Store>,
    frags: RwLock<HashMap<Vec<u8>, Arc<Frag>>>,
    total_bytes: AtomicU64,
    polls: Mutex<Polls>,
    shutdown: watch::Sender<bool>,
}

/// The relay. Cheap to clone; all clones share one state.
#[derive(Clone)]
pub struct Relay {
    inner: Arc<Inner>,
}

/// One registered long-poll. Dropping it (reply sent, or the client went
/// away and the request future was dropped) frees the slot.
struct PollGuard {
    inner: Arc<Inner>,
    fragment_id: Vec<u8>,
    rx: watch::Receiver<()>,
}

impl Drop for PollGuard {
    fn drop(&mut self) {
        let mut p = lock(&self.inner.polls);
        p.total = p.total.saturating_sub(1);
        if let Some(entry) = p.per.get_mut(&self.fragment_id) {
            entry.1 = entry.1.saturating_sub(1);
            if entry.1 == 0 {
                p.per.remove(&self.fragment_id);
            }
        }
    }
}

fn same_token(a: &TokenHash, b: &TokenHash) -> bool {
    // `blake3::Hash` equality is constant-time.
    blake3::Hash::from_bytes(*a) == blake3::Hash::from_bytes(*b)
}

fn valid_fragment_id(id: &[u8]) -> bool {
    !id.is_empty() && id.len() <= MAX_FRAGMENT_ID
}

fn empty_batch(fragment_id: &[u8], next: u64) -> Message {
    Message::Batch {
        fragment_id: fragment_id.to_vec(),
        next,
        more: false,
        sealed: Vec::new(),
    }
}

fn is_empty_batch(m: &Message) -> bool {
    matches!(m, Message::Batch { sealed, .. } if sealed.is_empty())
}

impl Relay {
    /// Build a relay on `store`, loading whatever the store already holds.
    pub fn new(cfg: Config, store: impl Store) -> io::Result<Relay> {
        cfg.validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut frags = HashMap::new();
        let mut total = 0u64;
        let mut item_count = 0u64;
        for f in store.load()? {
            if !valid_fragment_id(&f.fragment_id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "store returned an invalid fragment id",
                ));
            }
            let bytes: u64 = f
                .items
                .iter()
                .map(|(_, len)| u64::from(*len) + ITEM_OVERHEAD)
                .sum();
            total += bytes;
            item_count += f.items.len() as u64;
            let state = FragState {
                created: true,
                head: f.items.len() as u64,
                bytes,
                seen: f.items.iter().map(|(h, _)| *h).collect(),
            };
            frags.insert(
                f.fragment_id,
                Arc::new(Frag {
                    token_hash: f.token_hash,
                    state: Mutex::new(state),
                }),
            );
        }
        info!(
            "loaded",
            "fragments={} items={item_count} bytes={total}",
            frags.len()
        );
        Ok(Relay {
            inner: Arc::new(Inner {
                cfg,
                store: Box::new(store),
                frags: RwLock::new(frags),
                total_bytes: AtomicU64::new(total),
                polls: Mutex::new(Polls::default()),
                shutdown: watch::channel(false).0,
            }),
        })
    }

    /// The configuration this relay runs with.
    pub fn config(&self) -> &Config {
        &self.inner.cfg
    }

    /// Number of registered fragments.
    pub fn fragment_count(&self) -> usize {
        self.frags_read().len()
    }

    /// Number of long-polls currently held.
    pub fn poll_count(&self) -> usize {
        lock(&self.inner.polls).total
    }

    /// Make every held long-poll answer now (with an empty `Batch`) and
    /// later ones answer without waiting. Used during shutdown.
    pub fn begin_shutdown(&self) {
        self.inner.shutdown.send_replace(true);
    }

    fn frags_read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<Vec<u8>, Arc<Frag>>> {
        self.inner
            .frags
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lookup(&self, fragment_id: &[u8]) -> Option<Arc<Frag>> {
        self.frags_read().get(fragment_id).cloned()
    }

    fn notify(&self, fragment_id: &[u8]) {
        if let Some((tx, _)) = lock(&self.inner.polls).per.get(fragment_id) {
            tx.send_replace(());
        }
    }

    /// Handle a `Push`. Blocking (disk I/O): call from a blocking thread.
    ///
    /// All or nothing: if any check fails, no item of the push is stored.
    pub fn push(
        &self,
        token: &TokenHash,
        fragment_id: &[u8],
        sealed: &[SealedOp],
    ) -> Result<Message, Reject> {
        let cfg = &self.inner.cfg;
        if !valid_fragment_id(fragment_id) {
            return Err(Reject::new(400, "invalid fragment id"));
        }
        if sealed.len() > cfg.max_push_items {
            return Err(Reject::new(413, "too many items in one push"));
        }
        let mut items = Vec::with_capacity(sealed.len());
        for s in sealed {
            if s.fragment_id != fragment_id {
                return Err(Reject::new(
                    400,
                    "sealed item is addressed to a different fragment",
                ));
            }
            let bytes = s
                .to_bytes()
                .map_err(|_| Reject::new(400, "sealed item cannot be encoded"))?;
            if bytes.len() > cfg.max_item_bytes {
                return Err(Reject::new(413, "item too large"));
            }
            items.push(bytes);
        }
        let ack = |cursor| Message::Ack {
            fragment_id: fragment_id.to_vec(),
            cursor,
            count: u32::try_from(sealed.len()).unwrap_or(u32::MAX),
        };

        let existing = self.lookup(fragment_id);
        if let Some(f) = &existing
            && !same_token(&f.token_hash, token)
        {
            return Err(BAD_TOKEN);
        }
        if items.is_empty() {
            // Nothing to store, so nothing to register either.
            return Ok(ack(existing.map_or(0, |f| lock(&f.state).head)));
        }
        let f = match existing {
            Some(f) => f,
            None => self.register(fragment_id, token)?,
        };

        let mut st = lock(&f.state);
        if !st.created {
            if let Err(e) = self.inner.store.create(fragment_id, &f.token_hash) {
                warning!(
                    "store_error",
                    "op=create fragment={} kind={:?}",
                    frag(fragment_id),
                    e.kind()
                );
                // The registration stays (in memory only); the next push
                // tries to create the file again.
                return Err(STORAGE);
            }
            st.created = true;
        }

        // Byte-identical dedupe, against the log and within this push.
        let mut fresh = Vec::with_capacity(items.len());
        let mut fresh_hashes: Vec<[u8; 32]> = Vec::with_capacity(items.len());
        let mut add = 0u64;
        for item in items {
            let h = *blake3::hash(&item).as_bytes();
            if st.seen.contains(&h) || fresh_hashes.contains(&h) {
                continue;
            }
            add += item.len() as u64 + ITEM_OVERHEAD;
            fresh_hashes.push(h);
            fresh.push(item);
        }
        if fresh.is_empty() {
            return Ok(ack(st.head));
        }
        if st.bytes.saturating_add(add) > cfg.fragment_quota_bytes {
            return Err(Reject::new(413, "fragment quota exceeded"));
        }
        let total = self.inner.total_bytes.fetch_add(add, Ordering::SeqCst);
        if total.saturating_add(add) > cfg.total_quota_bytes {
            self.inner.total_bytes.fetch_sub(add, Ordering::SeqCst);
            return Err(Reject::new(507, "relay storage is full"));
        }
        if let Err(e) = self.inner.store.append(fragment_id, st.head + 1, &fresh) {
            self.inner.total_bytes.fetch_sub(add, Ordering::SeqCst);
            warning!(
                "store_error",
                "op=append fragment={} kind={:?}",
                frag(fragment_id),
                e.kind()
            );
            return Err(STORAGE);
        }
        st.head += fresh.len() as u64;
        st.bytes += add;
        st.seen.extend(fresh_hashes);
        let head = st.head;
        let used = st.bytes;
        drop(st);
        self.notify(fragment_id);
        info!(
            "push",
            "fragment={} items={} stored={} bytes={} head={head} used={used}",
            frag(fragment_id),
            sealed.len(),
            fresh.len(),
            add - fresh.len() as u64 * ITEM_OVERHEAD
        );
        Ok(ack(head))
    }

    fn register(&self, fragment_id: &[u8], token: &TokenHash) -> Result<Arc<Frag>, Reject> {
        let mut map = self
            .inner
            .frags
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(f) = map.get(fragment_id) {
            // Lost a race with another first push.
            return if same_token(&f.token_hash, token) {
                Ok(f.clone())
            } else {
                Err(BAD_TOKEN)
            };
        }
        if map.len() >= self.inner.cfg.max_fragments {
            return Err(Reject::new(507, "relay has no room for another fragment"));
        }
        let f = Arc::new(Frag {
            token_hash: *token,
            state: Mutex::new(FragState {
                created: false,
                head: 0,
                bytes: 0,
                seen: HashSet::new(),
            }),
        });
        map.insert(fragment_id.to_vec(), f.clone());
        info!(
            "register",
            "fragment={} fragments={}",
            frag(fragment_id),
            map.len()
        );
        Ok(f)
    }

    /// Answer a `Pull` from what is stored now, without waiting. Blocking
    /// (disk I/O): call from a blocking thread.
    ///
    /// An unregistered fragment yields an empty `Batch` and is not registered.
    /// `limit == 0` means "as many as the relay allows".
    pub fn pull_now(
        &self,
        token: &TokenHash,
        fragment_id: &[u8],
        after: u64,
        limit: u32,
    ) -> Result<Message, Reject> {
        let cfg = &self.inner.cfg;
        if !valid_fragment_id(fragment_id) {
            return Err(Reject::new(400, "invalid fragment id"));
        }
        let Some(f) = self.lookup(fragment_id) else {
            return Ok(empty_batch(fragment_id, 0));
        };
        if !same_token(&f.token_hash, token) {
            return Err(BAD_TOKEN);
        }
        let head = lock(&f.state).head;
        if after >= head {
            return Ok(empty_batch(fragment_id, head));
        }
        let limit = match limit as usize {
            0 => cfg.max_batch_items,
            n => n.min(cfg.max_batch_items),
        };
        let raw = self
            .inner
            .store
            .read(fragment_id, after, limit, cfg.max_batch_bytes)
            .map_err(|e| {
                warning!(
                    "store_error",
                    "op=read fragment={} kind={:?}",
                    frag(fragment_id),
                    e.kind()
                );
                STORAGE
            })?;
        let mut sealed = Vec::with_capacity(raw.len());
        let mut bytes = 0usize;
        for item in &raw {
            bytes += item.len();
            sealed.push(SealedOp::from_bytes(item).map_err(|_| STORAGE)?);
        }
        let next = after + sealed.len() as u64;
        info!(
            "pull",
            "fragment={} after={after} items={} bytes={bytes} next={next}",
            frag(fragment_id),
            sealed.len()
        );
        Ok(Message::Batch {
            fragment_id: fragment_id.to_vec(),
            next,
            more: next < head,
            sealed,
        })
    }

    fn register_poll(&self, fragment_id: &[u8]) -> Result<PollGuard, Reject> {
        let cfg = &self.inner.cfg;
        let mut p = lock(&self.inner.polls);
        if p.total >= cfg.max_polls {
            return Err(Reject::new(429, "too many long-polls on this relay"));
        }
        let rx = match p.per.get_mut(fragment_id) {
            Some((_, n)) if *n >= cfg.max_polls_per_fragment => {
                return Err(Reject::new(429, "too many long-polls on this fragment"));
            }
            Some((tx, n)) => {
                *n += 1;
                tx.subscribe()
            }
            None => {
                if cfg.max_polls_per_fragment == 0 {
                    return Err(Reject::new(429, "long-polls are disabled"));
                }
                let (tx, rx) = watch::channel(());
                p.per.insert(fragment_id.to_vec(), (tx, 1));
                rx
            }
        };
        p.total += 1;
        Ok(PollGuard {
            inner: self.inner.clone(),
            fragment_id: fragment_id.to_vec(),
            rx,
        })
    }

    async fn pull_blocking(
        &self,
        token: TokenHash,
        fragment_id: &[u8],
        after: u64,
        limit: u32,
    ) -> Result<Message, Reject> {
        let relay = self.clone();
        let id = fragment_id.to_vec();
        tokio::task::spawn_blocking(move || relay.pull_now(&token, &id, after, limit))
            .await
            .unwrap_or(Err(STORAGE))
    }

    /// Run [`Relay::push`] on the blocking pool.
    pub async fn push_async(
        &self,
        token: TokenHash,
        fragment_id: Vec<u8>,
        sealed: Vec<SealedOp>,
    ) -> Result<Message, Reject> {
        let relay = self.clone();
        tokio::task::spawn_blocking(move || relay.push(&token, &fragment_id, &sealed))
            .await
            .unwrap_or(Err(STORAGE))
    }

    /// Handle a `Pull`, holding it for up to `wait` (clamped to 25 s) while
    /// there is nothing after `after`.
    ///
    /// Past the long-poll caps the answer is `429`, not an empty `Batch`: an
    /// immediate empty reply would invite the client to retry in a tight loop.
    pub async fn pull(
        &self,
        token: TokenHash,
        fragment_id: &[u8],
        after: u64,
        limit: u32,
        wait: Duration,
    ) -> Result<Message, Reject> {
        let wait = wait.min(Duration::from_millis(crate::config::MAX_WAIT_MS));
        let first = self.pull_blocking(token, fragment_id, after, limit).await?;
        if wait.is_zero() || !is_empty_batch(&first) {
            return Ok(first);
        }
        let mut shutdown = self.inner.shutdown.subscribe();
        if *shutdown.borrow_and_update() {
            return Ok(first);
        }
        // Subscribe first, then look again: a push that lands in between
        // either shows up in the second look or flips the watch.
        let mut guard = self.register_poll(fragment_id)?;
        let deadline = Instant::now() + wait;
        loop {
            // Auth is re-checked here too: the fragment may have been
            // registered, with another token, while this request waited.
            let now = self.pull_blocking(token, fragment_id, after, limit).await?;
            if !is_empty_batch(&now) {
                return Ok(now);
            }
            tokio::select! {
                changed = tokio::time::timeout_at(deadline, guard.rx.changed()) => {
                    if !matches!(changed, Ok(Ok(()))) {
                        return Ok(now);
                    }
                }
                _ = shutdown.changed() => return Ok(now),
            }
        }
    }
}
