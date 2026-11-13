//! Pairing: the root secret and everything derived from it (SYNC-V0 section 2).

use gsp_wire::FragmentKey;
use zeroize::{Zeroize, Zeroizing};

/// BLAKE3 `derive_key` context of the fragment key.
pub const CTX_FRAGMENT_KEY: &str = "gsp/v0/fragment-key";
/// BLAKE3 `derive_key` context of the fragment id.
pub const CTX_FRAGMENT_ID: &str = "gsp/v0/fragment-id";
/// BLAKE3 `derive_key` context of the relay token.
pub const CTX_RELAY_TOKEN: &str = "gsp/v0/relay-token";
/// Prefix of the text form of a root secret.
pub const PAIRING_PREFIX: &str = "gsp0-";

/// Length of a fragment id derived by pairing.
pub const FRAGMENT_ID_LEN: usize = 16;

/// Why a pairing code was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    /// Does not start with `gsp0-`.
    Prefix,
    /// The part after the prefix is not exactly 43 characters.
    Length,
    /// A character outside the base64url alphabet (padding and whitespace
    /// included).
    Alphabet,
    /// The unused low bits of the last character are not zero, so this is not
    /// the one canonical spelling of its 32 bytes.
    NonCanonical,
}

impl core::fmt::Display for PairingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "gsp pairing code error: {self:?}")
    }
}
impl core::error::Error for PairingError {}

/// A fragment's 32-byte root secret. Whoever holds it is a device of the
/// owner. Zeroized on drop; `Debug` prints nothing secret.
#[derive(Clone)]
pub struct Pairing {
    root: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Pairing(<secret>)")
    }
}

impl Pairing {
    /// Wrap a root secret: 32 bytes from a CSPRNG, supplied by the caller.
    pub fn from_root(root: [u8; 32]) -> Pairing {
        Pairing {
            root: Zeroizing::new(root),
        }
    }

    /// The root secret itself.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Raw bytes of the fragment key: `derive_key("gsp/v0/fragment-key", root)`.
    pub fn fragment_key_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(CTX_FRAGMENT_KEY, &*self.root))
    }

    /// The fragment key, ready for sealing.
    pub fn fragment_key(&self) -> FragmentKey {
        FragmentKey::new(*self.fragment_key_bytes())
    }

    /// Public routing id: the first 16 bytes of
    /// `derive_key("gsp/v0/fragment-id", root)`.
    pub fn fragment_id(&self) -> [u8; FRAGMENT_ID_LEN] {
        let mut full = blake3::derive_key(CTX_FRAGMENT_ID, &*self.root);
        let mut id = [0u8; FRAGMENT_ID_LEN];
        for (o, i) in id.iter_mut().zip(full.iter()) {
            *o = *i;
        }
        full.zeroize();
        id
    }

    /// Bearer token for the relay: `derive_key("gsp/v0/relay-token", root)`.
    pub fn relay_token(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(CTX_RELAY_TOKEN, &*self.root))
    }

    /// Text form: `gsp0-` followed by the unpadded base64url of the 32 bytes.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut s = String::with_capacity(PAIRING_PREFIX.len() + 43);
        s.push_str(PAIRING_PREFIX);
        s.push_str(&base64url(&*self.root));
        Zeroizing::new(s)
    }

    /// Strict parse of the text form: exact prefix, exactly 43 characters of
    /// the base64url alphabet, no padding, no whitespace, canonical last
    /// character. Exactly one string parses to any given secret.
    pub fn parse(text: &str) -> Result<Pairing, PairingError> {
        let body = text
            .strip_prefix(PAIRING_PREFIX)
            .ok_or(PairingError::Prefix)?
            .as_bytes();
        if body.len() != 43 {
            return Err(PairingError::Length);
        }
        let mut root = Zeroizing::new([0u8; 32]);
        let mut acc: u32 = 0;
        let mut bits = 0u32;
        let mut out = root.iter_mut();
        for c in body {
            let v = match *c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => return Err(PairingError::Alphabet),
            };
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                if let Some(o) = out.next() {
                    *o = (acc >> bits) as u8;
                }
                acc &= (1 << bits) - 1;
            }
        }
        // 43 * 6 = 258 bits: two left over, which a canonical encoder zeroes.
        if acc != 0 {
            return Err(PairingError::NonCanonical);
        }
        Ok(Pairing { root })
    }
}

/// Unpadded base64url (RFC 4648 section 5), as used for the pairing code and
/// for the relay's `Authorization: Bearer` value.
pub fn base64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let sextet = |n: u32| char::from(ALPHABET[(n & 63) as usize]);
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut n: u32 = 0;
        for (i, b) in chunk.iter().enumerate() {
            n |= u32::from(*b) << (16 - 8 * i);
        }
        out.push(sextet(n >> 18));
        out.push(sextet(n >> 12));
        if chunk.len() > 1 {
            out.push(sextet(n >> 6));
        }
        if chunk.len() > 2 {
            out.push(sextet(n));
        }
    }
    out
}
