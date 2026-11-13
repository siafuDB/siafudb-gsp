//! The three-way verification result and the signature-set evaluator.

use crate::cbor::DecodeError;
use crate::registry::SigAlg;
use crate::types::{Domain, Multihash, PublicKey, RawCheck, Signature, sig_input, verify_raw};
use alloc::vec::Vec;

/// Result of verifying a signed object.
///
/// Only `Valid` may be applied. `Unverifiable` means "retain, do not apply,
/// re-check later" (newer software, a fresher key log or a later clock may
/// settle it). `Invalid` means the object is provably wrong for this verifier.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum Verdict<T> {
    /// Every check passed.
    Valid(T),
    /// Cannot be decided by this verifier right now. Never apply.
    Unverifiable {
        /// Why.
        reason: UnverifiableReason,
    },
    /// Rejected.
    Invalid {
        /// Why.
        reason: InvalidReason,
    },
}

impl<T> Verdict<T> {
    /// `true` only for `Valid`.
    pub fn is_valid(&self) -> bool {
        matches!(self, Verdict::Valid(_))
    }
    /// The verified value, if valid.
    pub fn valid(self) -> Option<T> {
        match self {
            Verdict::Valid(t) => Some(t),
            _ => None,
        }
    }
}

/// Why an object is retained but not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiableReason {
    /// `format` is newer than this build.
    UnknownFormat,
    /// The id's hash algorithm is not implemented here.
    UnknownHashAlg,
    /// No key log for the author is available.
    UnknownAuthor,
    /// A signature names a key that is not in the author's key log (the local
    /// copy of the log may be stale).
    UnknownKey,
    /// A signature uses an algorithm this build does not implement.
    UnknownSigAlg,
    /// The op's HLC is further ahead of local time than the allowed drift.
    HlcTooFarAhead,
}

/// Why an object is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidReason {
    /// Not canonical CBOR of the expected shape.
    Malformed(DecodeError),
    /// Signed for a different fragment than the one it arrived in.
    WrongFragment,
    /// No signatures at all.
    NoSignatures,
    /// A signature's algorithm differs from its key's algorithm.
    AlgMismatch,
    /// The signing key is not valid at this op's `seq` (revoked or not yet
    /// introduced).
    KeyNotValidAtSeq,
    /// A signature does not verify.
    BadSignature,
    /// The author's policy requires an algorithm for which no signature is
    /// present (downgrade attempt).
    MissingRequiredSignature,
}

/// How a signature's `key_id` resolved against a key log.
pub(crate) enum Resolved<'a> {
    Key(&'a PublicKey),
    NotValid,
    Unknown,
}

/// Evaluate a signature set against a policy. Rules:
///
/// 1. every signature present must verify (a bad one is fatal even if the
///    policy would be met without it);
/// 2. every algorithm in `required` must be covered by a good signature;
/// 3. anything that cannot be checked makes the result unverifiable, unless
///    rule 1 or 2 already made it invalid.
pub(crate) fn eval_sigs<'a>(
    sigs: &[Signature],
    required: &[u16],
    domain: Domain,
    audience: &[u8],
    id: &Multihash,
    resolve: impl Fn(&Signature) -> Resolved<'a>,
) -> Result<(), Verdict<core::convert::Infallible>> {
    let invalid = |reason| Err(Verdict::Invalid { reason });
    if sigs.is_empty() {
        return invalid(InvalidReason::NoSignatures);
    }
    let mut good: Vec<u16> = Vec::new();
    // (algorithm, reason) of each signature we could not check.
    let mut open: Vec<(u16, UnverifiableReason)> = Vec::new();
    for sig in sigs {
        let key = match resolve(sig) {
            Resolved::Key(k) => k,
            Resolved::NotValid => return invalid(InvalidReason::KeyNotValidAtSeq),
            Resolved::Unknown => {
                let why = if SigAlg::supported(sig.alg).is_some() {
                    UnverifiableReason::UnknownKey
                } else {
                    UnverifiableReason::UnknownSigAlg
                };
                open.push((sig.alg, why));
                continue;
            }
        };
        if key.alg != sig.alg {
            return invalid(InvalidReason::AlgMismatch);
        }
        let msg = sig_input(domain, audience, id, sig.alg, &sig.key_id);
        match verify_raw(key, &msg, &sig.bytes) {
            RawCheck::Good => good.push(sig.alg),
            RawCheck::Bad => return invalid(InvalidReason::BadSignature),
            RawCheck::UnknownAlg => open.push((sig.alg, UnverifiableReason::UnknownSigAlg)),
        }
    }
    for alg in required {
        if !good.contains(alg) && !open.iter().any(|(a, _)| a == alg) {
            return invalid(InvalidReason::MissingRequiredSignature);
        }
    }
    match open.first() {
        Some((_, reason)) => Err(Verdict::Unverifiable { reason: *reason }),
        None => Ok(()),
    }
}

/// Re-type an error verdict (which carries no payload).
pub(crate) fn retype<T>(v: Verdict<core::convert::Infallible>) -> Verdict<T> {
    match v {
        Verdict::Valid(never) => match never {},
        Verdict::Unverifiable { reason } => Verdict::Unverifiable { reason },
        Verdict::Invalid { reason } => Verdict::Invalid { reason },
    }
}
