//! Algorithm registries. Numeric, append-only, `0` reserved/invalid.
//!
//! Wire structures carry the raw `u16`, never the enum, so an id minted by a
//! newer peer survives a round trip through an older one. An id this build
//! does not implement makes the item `Unverifiable`; it is never treated as
//! valid and never silently dropped.

macro_rules! registry {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $var:ident = $id:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        pub enum $name { $($(#[$vm])* $var = $id),+ }
        impl $name {
            /// Registry id on the wire.
            pub const fn id(self) -> u16 { self as u16 }
            /// Look an id up; `None` if this build does not know it.
            pub const fn from_id(id: u16) -> Option<Self> {
                match id { $($id => Some(Self::$var),)+ _ => None }
            }
        }
    };
}

registry! {
    /// Signature algorithms. Hybrid = one `Signature` entry per algorithm.
    SigAlg {
        /// Ed25519 (RFC 8032), strict verification.
        Ed25519 = 1,
        /// ML-DSA-65 (FIPS 204), empty context string.
        MlDsa65 = 2,
    }
}
registry! {
    /// Hash algorithms (multihash style: the id travels with the digest).
    HashAlg {
        /// BLAKE3, 32-byte output. Default.
        Blake3_256 = 1,
        /// SHA3-256. Alternate.
        Sha3_256 = 2,
        /// SHA-256. Registered for interop; **not implemented by this crate**,
        /// so ids using it are `Unverifiable` here.
        Sha256 = 3,
    }
}
registry! {
    /// Key-exchange algorithms. Registry only: the hybrid handshake is out of
    /// scope for v0 of this crate.
    KemAlg {
        /// X25519.
        X25519 = 1,
        /// ML-KEM-768 (FIPS 203).
        MlKem768 = 2,
    }
}
registry! {
    /// AEAD algorithms.
    AeadAlg {
        /// XChaCha20-Poly1305, 24-byte nonce. The only one implemented.
        XChaCha20Poly1305 = 1,
        /// AES-256-GCM. Registered, not implemented by this crate.
        Aes256Gcm = 2,
    }
}
