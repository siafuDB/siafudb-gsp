//! Pairing: the root secret and everything derived from it (SYNC-V0 section 2).

use gsp_wire::FragmentKey;
use zeroize::Zeroizing;

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
        let full = Zeroizing::new(blake3::derive_key(CTX_FRAGMENT_ID, &*self.root));
        core::array::from_fn(|i| full[i])
    }

    /// Bearer token for the relay at `relay_origin`:
    /// `derive_key("gsp/v0/relay-token", root ‖ canonical_origin)`.
    ///
    /// The token is bound to the relay, so the operator of one relay cannot
    /// use what it is shown to claim the fragment on another. `relay_origin`
    /// is normalised with [`canonical_origin`] first; an origin that cannot
    /// be normalised is an error.
    pub fn relay_token(&self, relay_origin: &str) -> Result<Zeroizing<[u8; 32]>, OriginError> {
        let origin = canonical_origin(relay_origin)?;
        let mut material = Zeroizing::new(Vec::with_capacity(32 + origin.len()));
        material.extend_from_slice(&*self.root);
        material.extend_from_slice(origin.as_bytes());
        Ok(Zeroizing::new(blake3::derive_key(
            CTX_RELAY_TOKEN,
            &material,
        )))
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
        let mut decoded: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(33));
        let mut acc: u32 = 0;
        let mut bits = 0u32;
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
                decoded.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        // 43 * 6 = 258 bits: two left over, which a canonical encoder zeroes.
        if acc != 0 {
            return Err(PairingError::NonCanonical);
        }
        let root: Zeroizing<[u8; 32]> = Zeroizing::new(
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| PairingError::Length)?,
        );
        Ok(Pairing { root })
    }
}

/// Why a relay origin was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginError {
    /// Not `http://` or `https://`.
    Scheme,
    /// Empty host, or a host with characters outside `a-z 0-9 - .` (write
    /// internationalised names in their `xn--` form), or a malformed
    /// bracketed IPv6 literal.
    Host,
    /// A port that is not a decimal number from 1 to 65535.
    Port,
    /// Something after the host and port: a path, query, fragment or user
    /// info. An origin has none of these.
    Extra,
}

impl core::fmt::Display for OriginError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "gsp relay origin error: {self:?}")
    }
}
impl core::error::Error for OriginError {}

/// The canonical form of a relay origin, as bound into the relay token
/// (SYNC-V0 section 2): `scheme://host[:port]`, where
///
/// - `scheme` is `http` or `https`, lowercase;
/// - `host` is a lowercase ASCII host name or IPv4 address, or an IPv6
///   address in brackets with lowercase hex digits (and otherwise as given:
///   zero compression is not normalised);
/// - `port` is decimal without leading zeros and is omitted when it is the
///   scheme's default (80 for `http`, 443 for `https`);
/// - nothing follows: no path, no trailing slash, no query, no fragment.
///
/// The input may differ from that in letter case, by an explicit default
/// port, by leading zeros in the port and by one trailing `/`; anything else
/// is an error.
pub fn canonical_origin(origin: &str) -> Result<String, OriginError> {
    let (scheme, rest) = origin.split_once("://").ok_or(OriginError::Scheme)?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80u16,
        "https" => 443,
        _ => return Err(OriginError::Scheme),
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains(['/', '?', '#', '@']) {
        return Err(OriginError::Extra);
    }
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (addr, after) = v6.split_once(']').ok_or(OriginError::Host)?;
        if addr.is_empty()
            || !addr.contains(':')
            || !addr
                .bytes()
                .all(|c| c.is_ascii_hexdigit() || c == b':' || c == b'.')
        {
            return Err(OriginError::Host);
        }
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return Err(OriginError::Host),
        };
        (format!("[{}]", addr.to_ascii_lowercase()), port)
    } else {
        let (host, port) = match rest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        if host.is_empty()
            || !host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
        {
            return Err(OriginError::Host);
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 16 || !p.bytes().all(|c| c.is_ascii_digit()) {
                return Err(OriginError::Port);
            }
            match p.parse::<u16>() {
                Ok(0) | Err(_) => return Err(OriginError::Port),
                Ok(n) if n == default_port => None,
                Ok(n) => Some(n),
            }
        }
    };
    Ok(match port {
        Some(n) => format!("{scheme}://{host}:{n}"),
        None => format!("{scheme}://{host}"),
    })
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
