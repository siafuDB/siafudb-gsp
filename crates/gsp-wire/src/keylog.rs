//! The author key log: a hash-chained, self-authenticating list of key and
//! policy changes. It is where a verifier learns which keys an author has and
//! which signature algorithms the author *requires*; an op cannot lower its
//! own bar.
//!
//! A key log is bound to one fragment (the genesis entry carries the fragment
//! id). The author id is the content id of the genesis entry. Validity of keys
//! and policies is expressed as positions in the author's op chain (`seq`),
//! never as wall-clock time.

use crate::cbor::{DecodeError, EncodeError, Fields, Value, u16_list};
use crate::registry::SigAlg;
use crate::types::{
    Domain, FORMAT_V0, Multihash, PublicKey, Signed, SigningKey, check_fragment_id,
};
use crate::verdict::{Resolved, Verdict, eval_sigs};
use alloc::{vec, vec::Vec};

/// What a key-log entry does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLogAction {
    /// First entry. Declares the fragment, the initial keys (valid from
    /// `seq` 1) and the initial policy. CBOR: `[1, fragment_id, [* PublicKey], [* uint]]`.
    Genesis {
        /// Fragment this author identity writes to.
        fragment_id: Vec<u8>,
        /// Initial keys. Each must sign the entry (proof of possession).
        keys: Vec<PublicKey>,
        /// Required signature algorithms: every one must sign every op.
        policy: Vec<u16>,
    },
    /// Introduce a key valid for ops with `seq >= from_seq`.
    /// CBOR: `[2, PublicKey, from_seq]`. The new key must co-sign.
    AddKey {
        /// The key.
        key: PublicKey,
        /// First op `seq` it may sign.
        from_seq: u64,
    },
    /// Revoke a key: ops with `seq > after_seq` signed by it are invalid; ops
    /// with `seq <= after_seq` stay valid. CBOR: `[3, key_id, after_seq]`.
    RevokeKey {
        /// Fingerprint of the key (hash algorithm = the entry's `hash_alg`).
        key_id: Multihash,
        /// Last op `seq` the key is trusted for. `0` distrusts everything.
        after_seq: u64,
    },
    /// Change the required algorithms for ops with `seq >= from_seq`.
    /// CBOR: `[4, [* uint], from_seq]`.
    SetPolicy {
        /// Required signature algorithms.
        policy: Vec<u16>,
        /// First op `seq` the policy applies to.
        from_seq: u64,
    },
}

/// Body of a key-log entry. CBOR: `[format, hash_alg, prev, action]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLogEntry {
    /// Hash algorithm for this entry's id and for key ids inside it.
    pub hash_alg: u16,
    /// Id of the previous entry; `None` only for genesis.
    pub prev: Option<Multihash>,
    /// The change.
    pub action: KeyLogAction,
}

fn check_policy(p: &[u16]) -> bool {
    !p.is_empty() && p.len() <= 8 && p.windows(2).all(|w| w[0] < w[1]) && p[0] != 0
}

impl KeyLogEntry {
    /// Canonical bytes of the body.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let action = match &self.action {
            KeyLogAction::Genesis {
                fragment_id,
                keys,
                policy,
            } => vec![
                Value::uint(1),
                Value::Bytes(fragment_id.clone()),
                Value::Array(keys.iter().map(PublicKey::to_value).collect()),
                u16_list(policy),
            ],
            KeyLogAction::AddKey { key, from_seq } => {
                vec![Value::uint(2), key.to_value(), Value::uint(*from_seq)]
            }
            KeyLogAction::RevokeKey { key_id, after_seq } => {
                vec![Value::uint(3), key_id.to_value(), Value::uint(*after_seq)]
            }
            KeyLogAction::SetPolicy { policy, from_seq } => {
                vec![Value::uint(4), u16_list(policy), Value::uint(*from_seq)]
            }
        };
        Value::Array(vec![
            Value::uint(u64::from(FORMAT_V0)),
            Value::uint(u64::from(self.hash_alg)),
            Multihash::opt_to_value(&self.prev),
            Value::Array(action),
        ])
        .encode()
    }

    /// Strict parse of body bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyLogEntry, DecodeError> {
        const W: &str = "key log entry";
        let v = Value::decode(bytes)?;
        let mut f = Fields::open(&v, W)?;
        let format = f.u64()?;
        if format != u64::from(FORMAT_V0) {
            return Err(DecodeError::UnsupportedFormat(format));
        }
        let hash_alg = f.u16()?;
        let prev = Multihash::opt_from_value(f.value()?)?;
        let mut a = Fields::open(f.value()?, W)?;
        f.end()?;
        let action = match a.u64()? {
            1 => {
                let fragment_id = a.bytes()?.to_vec();
                let keys = a
                    .array()?
                    .iter()
                    .map(PublicKey::from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                let policy = a.u16_list()?;
                if !check_fragment_id(&fragment_id) || keys.is_empty() || keys.len() > 16 {
                    return Err(DecodeError::Shape(W));
                }
                KeyLogAction::Genesis {
                    fragment_id,
                    keys,
                    policy,
                }
            }
            2 => KeyLogAction::AddKey {
                key: PublicKey::from_value(a.value()?)?,
                from_seq: a.u64()?,
            },
            3 => KeyLogAction::RevokeKey {
                key_id: Multihash::from_value(a.value()?)?,
                after_seq: a.u64()?,
            },
            4 => KeyLogAction::SetPolicy {
                policy: a.u16_list()?,
                from_seq: a.u64()?,
            },
            other => return Err(DecodeError::UnsupportedKind(other)),
        };
        a.end()?;
        let ok = match &action {
            KeyLogAction::Genesis { policy, .. } => check_policy(policy) && prev.is_none(),
            KeyLogAction::AddKey { from_seq, .. } => *from_seq >= 1 && prev.is_some(),
            KeyLogAction::RevokeKey { .. } => prev.is_some(),
            KeyLogAction::SetPolicy { policy, from_seq } => {
                check_policy(policy) && *from_seq >= 1 && prev.is_some()
            }
        };
        if !ok {
            return Err(DecodeError::Shape(W));
        }
        Ok(KeyLogEntry {
            hash_alg,
            prev,
            action,
        })
    }

    /// Encode and sign. Returns the bytes of the signed envelope
    /// (`[body: bstr, sigs]`), ready for [`KeyLog::genesis`] / [`KeyLog::append`].
    pub fn sign(&self, keys: &[&SigningKey]) -> Result<Vec<u8>, EncodeError> {
        let body = self.to_bytes()?;
        let id =
            Multihash::compute(self.hash_alg, &body).ok_or(EncodeError::Limit("hash algorithm"))?;
        Signed::sign(Domain::KeyLog, &[], &id, body, keys)?.to_bytes()
    }
}

/// Why an entry was not accepted into a [`KeyLog`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLogError {
    /// Not canonical CBOR of the right shape.
    Malformed(DecodeError),
    /// Uses a format, hash or signature algorithm this build cannot check.
    /// The log cannot advance past such an entry on this build.
    Unsupported,
    /// `prev` is not the current head (a gap, a replay, or a fork of the log).
    NotHead,
    /// The first entry is not a genesis, or a later one is.
    Genesis,
    /// Signatures do not satisfy the log's current policy, or one is bad.
    Unauthorized,
    /// The entry refers to a key the log does not hold, re-adds a key, or
    /// leaves a required algorithm with no key at all.
    Inconsistent,
}

impl core::fmt::Display for KeyLogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "gsp key log error: {self:?}")
    }
}
impl core::error::Error for KeyLogError {}

/// A key with its validity window in op-`seq` space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyState {
    /// The key.
    pub key: PublicKey,
    /// Fingerprint under the log's hash algorithm.
    pub key_id: Multihash,
    /// First op `seq` this key may sign.
    pub from_seq: u64,
    /// If revoked: last op `seq` this key is trusted for.
    pub revoked_after: Option<u64>,
}

impl KeyState {
    /// May this key sign an op at `seq`?
    pub fn valid_at(&self, seq: u64) -> bool {
        self.from_seq <= seq && self.revoked_after.is_none_or(|n| seq <= n)
    }
}

/// A verified key log for one author in one fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLog {
    author: Multihash,
    fragment_id: Vec<u8>,
    head: Multihash,
    keys: Vec<KeyState>,
    /// `(from_seq, required algorithms)` in append order.
    policies: Vec<(u64, Vec<u16>)>,
    entries: Vec<Vec<u8>>,
}

impl KeyLog {
    /// Start a log from signed genesis bytes. The caller decides whether to
    /// trust this author at all; the log only proves internal consistency.
    pub fn genesis(signed: &[u8]) -> Result<KeyLog, KeyLogError> {
        let (env, entry, id) = parse(signed)?;
        let KeyLogAction::Genesis {
            fragment_id,
            keys,
            policy,
        } = entry.action
        else {
            return Err(KeyLogError::Genesis);
        };
        if policy.iter().any(|a| SigAlg::from_id(*a).is_none()) {
            return Err(KeyLogError::Unsupported);
        }
        let mut states = Vec::new();
        for key in keys {
            let key_id = key.key_id(entry.hash_alg).ok_or(KeyLogError::Unsupported)?;
            if states.iter().any(|s: &KeyState| s.key_id == key_id) {
                return Err(KeyLogError::Inconsistent);
            }
            states.push(KeyState {
                key,
                key_id,
                from_seq: 1,
                revoked_after: None,
            });
        }
        // Proof of possession: every declared key signs, plus the policy holds.
        if env.sigs.len() != states.len() {
            return Err(KeyLogError::Unauthorized);
        }
        authorize(&env, &id, &policy, &states, None)?;
        let log = KeyLog {
            author: id.clone(),
            fragment_id,
            head: id,
            keys: states,
            policies: vec![(1, policy)],
            entries: vec![signed.to_vec()],
        };
        log.check_satisfiable()?;
        Ok(log)
    }

    /// Append the next signed entry. On error the log is unchanged.
    pub fn append(&mut self, signed: &[u8]) -> Result<Multihash, KeyLogError> {
        let (env, entry, id) = parse(signed)?;
        if entry.prev.as_ref() != Some(&self.head) {
            return Err(match entry.action {
                KeyLogAction::Genesis { .. } => KeyLogError::Genesis,
                _ => KeyLogError::NotHead,
            });
        }
        let mut next = self.clone();
        let mut extra: Option<KeyState> = None;
        match entry.action {
            KeyLogAction::Genesis { .. } => return Err(KeyLogError::Genesis),
            KeyLogAction::AddKey { key, from_seq } => {
                let key_id = key.key_id(self.head.alg).ok_or(KeyLogError::Unsupported)?;
                if self.keys.iter().any(|s| s.key_id == key_id) {
                    return Err(KeyLogError::Inconsistent);
                }
                let st = KeyState {
                    key,
                    key_id,
                    from_seq,
                    revoked_after: None,
                };
                // The new key must co-sign (proof of possession).
                if !env.sigs.iter().any(|s| s.key_id == st.key_id) {
                    return Err(KeyLogError::Unauthorized);
                }
                next.keys.push(st.clone());
                extra = Some(st);
            }
            KeyLogAction::RevokeKey { key_id, after_seq } => {
                let st = next
                    .keys
                    .iter_mut()
                    .find(|s| s.key_id == key_id)
                    .ok_or(KeyLogError::Inconsistent)?;
                // A revocation can only tighten.
                st.revoked_after = Some(st.revoked_after.map_or(after_seq, |n| n.min(after_seq)));
            }
            KeyLogAction::SetPolicy { policy, from_seq } => {
                if policy.iter().any(|a| SigAlg::from_id(*a).is_none()) {
                    return Err(KeyLogError::Unsupported);
                }
                next.policies.push((from_seq, policy));
            }
        }
        authorize(&env, &id, self.log_policy(), &self.keys, extra.as_ref())?;
        next.check_satisfiable()?;
        next.head = id.clone();
        next.entries.push(signed.to_vec());
        *self = next;
        Ok(id)
    }

    /// Rebuild a log from its signed entries, genesis first.
    pub fn from_entries<'a>(
        mut entries: impl Iterator<Item = &'a [u8]>,
    ) -> Result<KeyLog, KeyLogError> {
        let mut log = KeyLog::genesis(entries.next().ok_or(KeyLogError::Genesis)?)?;
        for e in entries {
            log.append(e)?;
        }
        Ok(log)
    }

    /// The signed entries, genesis first, as accepted.
    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }
    /// The author id: content id of the genesis entry.
    pub fn author(&self) -> &Multihash {
        &self.author
    }
    /// The fragment this author identity is bound to.
    pub fn fragment_id(&self) -> &[u8] {
        &self.fragment_id
    }
    /// Id of the latest entry. Two peers holding different heads of equal
    /// length for one author have evidence of a forked key log.
    pub fn head(&self) -> &Multihash {
        &self.head
    }
    /// All keys ever added, with validity windows.
    pub fn keys(&self) -> &[KeyState] {
        &self.keys
    }

    /// Required signature algorithms for an op at `seq`: the policy with the
    /// greatest `from_seq <= seq`; among equals, the one appended last.
    pub fn policy_at(&self, seq: u64) -> &[u16] {
        let mut best = &self.policies[0];
        for p in &self.policies {
            if p.0 <= seq && p.0 >= best.0 {
                best = p;
            }
        }
        &best.1
    }

    /// Policy that key-log entries themselves must satisfy: the most recently
    /// appended one.
    fn log_policy(&self) -> &[u16] {
        &self.policies[self.policies.len() - 1].1
    }

    /// Find a key by fingerprint (any hash algorithm this build implements).
    pub fn find_key(&self, key_id: &Multihash) -> Option<&KeyState> {
        self.keys.iter().find(|s| {
            if s.key_id.alg == key_id.alg {
                s.key_id == *key_id
            } else {
                s.key.key_id(key_id.alg).as_ref() == Some(key_id)
            }
        })
    }

    /// Every algorithm the latest policy requires must still have an
    /// unrevoked key, or the log (and the author) would be dead.
    fn check_satisfiable(&self) -> Result<(), KeyLogError> {
        let ok = self.log_policy().iter().all(|alg| {
            self.keys
                .iter()
                .any(|k| k.key.alg == *alg && k.revoked_after.is_none())
        });
        if ok {
            Ok(())
        } else {
            Err(KeyLogError::Inconsistent)
        }
    }
}

fn parse(signed: &[u8]) -> Result<(Signed, KeyLogEntry, Multihash), KeyLogError> {
    let env = Signed::from_bytes(signed).map_err(KeyLogError::Malformed)?;
    let entry = KeyLogEntry::from_bytes(&env.body).map_err(|e| match e {
        DecodeError::UnsupportedFormat(_) | DecodeError::UnsupportedKind(_) => {
            KeyLogError::Unsupported
        }
        e => KeyLogError::Malformed(e),
    })?;
    // The id is the hash of the bytes as received.
    let id = Multihash::compute(entry.hash_alg, &env.body).ok_or(KeyLogError::Unsupported)?;
    if entry.prev.as_ref().is_some_and(|p| p.alg != entry.hash_alg) {
        return Err(KeyLogError::Unsupported);
    }
    Ok((env, entry, id))
}

/// Entry signatures: by unrevoked keys of the log (plus the key being added),
/// all good, covering every algorithm of `policy`.
fn authorize(
    env: &Signed,
    id: &Multihash,
    policy: &[u16],
    keys: &[KeyState],
    extra: Option<&KeyState>,
) -> Result<(), KeyLogError> {
    let res = eval_sigs(&env.sigs, policy, Domain::KeyLog, &[], id, |sig| match keys
        .iter()
        .chain(extra)
        .find(|k| k.key_id == sig.key_id)
    {
        Some(k) if k.revoked_after.is_none() => Resolved::Key(&k.key),
        Some(_) => Resolved::NotValid,
        None => Resolved::Unknown,
    });
    match res {
        Ok(()) => Ok(()),
        Err(Verdict::Unverifiable {
            reason: crate::verdict::UnverifiableReason::UnknownSigAlg,
        }) => Err(KeyLogError::Unsupported),
        Err(_) => Err(KeyLogError::Unauthorized),
    }
}

/// Lookup of key logs by author id, supplied by the caller of `verify`.
pub trait KeyLogs {
    /// The key log for `author`, if known.
    fn get(&self, author: &Multihash) -> Option<&KeyLog>;
}
impl KeyLogs for KeyLog {
    fn get(&self, author: &Multihash) -> Option<&KeyLog> {
        (self.author == *author).then_some(self)
    }
}
impl KeyLogs for [KeyLog] {
    fn get(&self, author: &Multihash) -> Option<&KeyLog> {
        self.iter().find(|l| l.author == *author)
    }
}
impl KeyLogs for Vec<KeyLog> {
    fn get(&self, author: &Multihash) -> Option<&KeyLog> {
        KeyLogs::get(self.as_slice(), author)
    }
}
