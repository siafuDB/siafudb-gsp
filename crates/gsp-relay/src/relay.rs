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
use tokio::sync::Semaphore;
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

/// What a request presented: the hash of its bearer relay token and, if the
/// `x-gsp-registration` header was sent, the hash of that value.
#[derive(Debug, Clone, Copy)]
pub struct Auth {
    /// `BLAKE3(relay_token)`.
    pub token: TokenHash,
    /// `BLAKE3` of the registration secret the client sent, if any.
    pub registration: Option<TokenHash>,
}

impl Auth {
    /// Credentials with a relay token only.
    pub fn token(token: TokenHash) -> Auth {
        Auth {
            token,
            registration: None,
        }
    }
}

const BUSY: Reject = Reject::new(503, "relay is busy decoding other requests");
const BAD_TOKEN: Reject = Reject::new(401, "relay token rejected for this fragment");
const STORAGE: Reject = Reject::new(500, "storage error");

struct FragState {
    /// Cursor of the last stored item. Never 0: a fragment is registered
    /// only together with its first item.
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
    /// Serializes first pushes (registration), so limits are checked and the
    /// store is written before a fragment becomes visible.
    registering: Mutex<()>,
    /// `BLAKE3` of the operator's registration secret, if one is set.
    registration: Option<TokenHash>,
    /// Bounds the request bytes being decoded at once.
    decode: Arc<Semaphore>,
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

impl Relay {
    /// Build a relay on `store`, loading whatever the store already holds.
    pub fn new(cfg: Config, store: impl Store) -> io::Result<Relay> {
        cfg.validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut frags = HashMap::new();
        let mut total = 0u64;
        let mut item_count = 0u64;
        let mut purged = 0usize;
        for f in store.load()? {
            if !valid_fragment_id(&f.fragment_id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "store returned an invalid fragment id",
                ));
            }
            if f.items.is_empty() {
                // Left by a crash between creating a fragment and storing its
                // first item (or by a torn first record). No push to it was
                // ever acknowledged; do not bring the registration back.
                store.remove(&f.fragment_id)?;
                purged += 1;
                continue;
            }
            let bytes: u64 = f
                .items
                .iter()
                .map(|(_, len)| u64::from(*len) + ITEM_OVERHEAD)
                .sum();
            total += bytes;
            item_count += f.items.len() as u64;
            let state = FragState {
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
            "fragments={} items={item_count} bytes={total} purged_empty={purged}",
            frags.len()
        );
        let registration = cfg
            .registration_token
            .as_ref()
            .map(|t| *blake3::hash(t.expose().as_bytes()).as_bytes());
        let decode = Arc::new(Semaphore::new(cfg.max_decode_bytes));
        Ok(Relay {
            inner: Arc::new(Inner {
                cfg,
                store: Box::new(store),
                frags: RwLock::new(frags),
                registering: Mutex::new(()),
                registration,
                decode,
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

    fn may_register(&self, auth: &Auth) -> Result<(), Reject> {
        match (&self.inner.registration, &auth.registration) {
            (None, _) => Ok(()),
            (Some(want), Some(got)) if same_token(want, got) => Ok(()),
            _ => Err(Reject::new(
                403,
                "this relay requires a registration secret for new fragments",
            )),
        }
    }

    /// The checks that need only the fragment id, so a request can be turned
    /// away before its body is decoded: the relay token for a registered
    /// fragment, the registration secret for a new one.
    pub fn preauth(&self, auth: &Auth, fragment_id: &[u8]) -> Result<(), Reject> {
        match self.lookup(fragment_id) {
            Some(f) if same_token(&f.token_hash, &auth.token) => Ok(()),
            Some(_) => Err(BAD_TOKEN),
            None => self.may_register(auth),
        }
    }

    /// Handle a `Push`. Blocking (disk I/O): call from a blocking thread.
    ///
    /// All or nothing: if any check fails, no item of the push is stored. A
    /// refused first push leaves nothing behind: the fragment is not
    /// registered and the store is not touched.
    pub fn push(
        &self,
        auth: &Auth,
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
        let count = u32::try_from(sealed.len()).unwrap_or(u32::MAX);
        let ack = |cursor| Message::Ack {
            fragment_id: fragment_id.to_vec(),
            cursor,
            count,
        };

        let f = match self.lookup(fragment_id) {
            Some(f) => f,
            None if items.is_empty() => {
                // Nothing to store, so nothing to register either.
                self.may_register(auth)?;
                return Ok(ack(0));
            }
            None => {
                let _registering = lock(&self.inner.registering);
                match self.lookup(fragment_id) {
                    // Lost a race with another first push.
                    Some(f) => f,
                    None => {
                        let head = self.register(auth, fragment_id, items, count)?;
                        return Ok(ack(head));
                    }
                }
            }
        };
        if !same_token(&f.token_hash, &auth.token) {
            return Err(BAD_TOKEN);
        }

        let mut st = lock(&f.state);
        let (fresh, hashes, add) = dedupe(Some(&st.seen), items);
        if fresh.is_empty() {
            return Ok(ack(st.head));
        }
        if st.bytes.saturating_add(add) > cfg.fragment_quota_bytes {
            return Err(Reject::new(413, "fragment quota exceeded"));
        }
        self.reserve(add)?;
        if let Err(e) = self.inner.store.append(fragment_id, st.head + 1, &fresh) {
            self.release(add);
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
        st.seen.extend(hashes);
        let head = st.head;
        let used = st.bytes;
        drop(st);
        self.notify(fragment_id);
        info!(
            "push",
            "fragment={} items={count} stored={} bytes={} head={head} used={used}",
            frag(fragment_id),
            fresh.len(),
            add - fresh.len() as u64 * ITEM_OVERHEAD
        );
        Ok(ack(head))
    }

    fn reserve(&self, add: u64) -> Result<(), Reject> {
        let before = self.inner.total_bytes.fetch_add(add, Ordering::SeqCst);
        if before.saturating_add(add) > self.inner.cfg.total_quota_bytes {
            self.release(add);
            return Err(Reject::new(507, "relay storage is full"));
        }
        Ok(())
    }

    fn release(&self, add: u64) {
        self.inner.total_bytes.fetch_sub(add, Ordering::SeqCst);
    }

    /// First non-empty push to an unregistered fragment. The caller holds
    /// the `registering` lock. Every limit is checked before the store is
    /// touched, and the fragment becomes visible only once its first items
    /// are stored. Returns the new head.
    fn register(
        &self,
        auth: &Auth,
        fragment_id: &[u8],
        items: Vec<Vec<u8>>,
        count: u32,
    ) -> Result<u64, Reject> {
        let cfg = &self.inner.cfg;
        self.may_register(auth)?;
        if self.fragment_count() >= cfg.max_fragments {
            return Err(Reject::new(507, "relay has no room for another fragment"));
        }
        let (fresh, hashes, add) = dedupe(None, items);
        if add > cfg.fragment_quota_bytes {
            return Err(Reject::new(413, "fragment quota exceeded"));
        }
        self.reserve(add)?;
        let store = &self.inner.store;
        let stored = store.create(fragment_id, &auth.token).and_then(|()| {
            store.append(fragment_id, 1, &fresh).inspect_err(|_| {
                // Take the empty fragment back out. If even that fails, the
                // next start removes it (it holds no items).
                let _ = store.remove(fragment_id);
            })
        });
        if let Err(e) = stored {
            self.release(add);
            warning!(
                "store_error",
                "op=register fragment={} kind={:?}",
                frag(fragment_id),
                e.kind()
            );
            return Err(STORAGE);
        }
        let head = fresh.len() as u64;
        let f = Arc::new(Frag {
            token_hash: auth.token,
            state: Mutex::new(FragState {
                head,
                bytes: add,
                seen: hashes.into_iter().collect(),
            }),
        });
        let mut map = self
            .inner
            .frags
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.insert(fragment_id.to_vec(), f);
        info!(
            "register",
            "fragment={} fragments={} items={count} stored={head} used={add}",
            frag(fragment_id),
            map.len()
        );
        Ok(head)
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
        self.pull_step(token, fragment_id, after, limit)
            .map(|(m, _)| m)
    }

    /// As [`Relay::pull_now`], plus whether the request may be held as a
    /// long-poll: only for a registered fragment, the right token, and
    /// `after` exactly at the head.
    fn pull_step(
        &self,
        token: &TokenHash,
        fragment_id: &[u8],
        after: u64,
        limit: u32,
    ) -> Result<(Message, bool), Reject> {
        let cfg = &self.inner.cfg;
        if !valid_fragment_id(fragment_id) {
            return Err(Reject::new(400, "invalid fragment id"));
        }
        let Some(f) = self.lookup(fragment_id) else {
            // Never held: anyone can ask about any id, so waiting here would
            // let strangers use up the long-poll slots.
            return Ok((empty_batch(fragment_id, 0), false));
        };
        if !same_token(&f.token_hash, token) {
            return Err(BAD_TOKEN);
        }
        let head = lock(&f.state).head;
        if after >= head {
            // `after > head` means the client is ahead of this relay (the
            // relay lost data and renumbered). Answer at once so the client
            // sees `next < after` and can react.
            return Ok((empty_batch(fragment_id, head), after == head));
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
        let batch = Message::Batch {
            fragment_id: fragment_id.to_vec(),
            next,
            more: next < head,
            sealed,
        };
        Ok((batch, false))
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
    ) -> Result<(Message, bool), Reject> {
        let relay = self.clone();
        let id = fragment_id.to_vec();
        tokio::task::spawn_blocking(move || relay.pull_step(&token, &id, after, limit))
            .await
            .unwrap_or(Err(STORAGE))
    }

    /// Run [`Relay::push`] on the blocking pool.
    pub async fn push_async(
        &self,
        auth: Auth,
        fragment_id: Vec<u8>,
        sealed: Vec<SealedOp>,
    ) -> Result<Message, Reject> {
        let relay = self.clone();
        tokio::task::spawn_blocking(move || relay.push(&auth, &fragment_id, &sealed))
            .await
            .unwrap_or(Err(STORAGE))
    }

    /// Decode a `Push` frame and handle it, both on the blocking pool.
    ///
    /// At most [`Config::max_decode_bytes`] of request bodies are being
    /// decoded at any moment; a body that does not fit right now is refused
    /// with `503` instead of queued.
    pub async fn push_encoded(&self, auth: Auth, body: Vec<u8>) -> Result<Message, Reject> {
        let permits = u32::try_from(body.len().max(1)).map_err(|_| BUSY)?;
        let permit = self
            .inner
            .decode
            .clone()
            .try_acquire_many_owned(permits)
            .map_err(|_| BUSY)?;
        let relay = self.clone();
        tokio::task::spawn_blocking(move || {
            let decoded = Message::from_bytes(&body);
            drop(body);
            let result = match decoded {
                Ok(Message::Push {
                    fragment_id,
                    sealed,
                }) => relay.push(&auth, &fragment_id, &sealed),
                Ok(_) => Err(Reject::new(400, "expected a Push frame")),
                Err(_) => Err(Reject::new(400, "malformed frame")),
            };
            drop(permit);
            result
        })
        .await
        .unwrap_or(Err(STORAGE))
    }

    /// Handle a `Pull`, holding it for up to `wait` (clamped to 25 s) while
    /// there is nothing after `after`.
    ///
    /// A pull is held only when the fragment is registered, the token is
    /// right, and `after` equals the fragment's head. A pull on an
    /// unregistered fragment, or with `after` beyond the head, is answered
    /// at once whatever `wait` says.
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
        let (first, may_wait) = self.pull_blocking(token, fragment_id, after, limit).await?;
        if wait.is_zero() || !may_wait {
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
            let (now, may_wait) = self.pull_blocking(token, fragment_id, after, limit).await?;
            if !may_wait {
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

/// Byte-identical dedupe against `seen` and within the push itself. Returns
/// the items to store, their hashes, and the bytes they are charged.
fn dedupe(
    seen: Option<&HashSet<[u8; 32]>>,
    items: Vec<Vec<u8>>,
) -> (Vec<Vec<u8>>, Vec<[u8; 32]>, u64) {
    let mut fresh = Vec::with_capacity(items.len());
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(items.len());
    let mut add = 0u64;
    for item in items {
        let h = *blake3::hash(&item).as_bytes();
        if seen.is_some_and(|s| s.contains(&h)) || hashes.contains(&h) {
            continue;
        }
        add += item.len() as u64 + ITEM_OVERHEAD;
        hashes.push(h);
        fresh.push(item);
    }
    (fresh, hashes, add)
}
