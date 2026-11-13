//! Pairing: derivation with the exact context strings of SYNC-V0 section 2,
//! and the strict text form.
use gsp_sync::*;

#[test]
fn derivations_use_the_spec_contexts() {
    let root = [7u8; 32];
    let p = Pairing::from_root(root);
    assert_eq!(
        *p.fragment_key_bytes(),
        blake3::derive_key("gsp/v0/fragment-key", &root)
    );
    assert_eq!(
        p.fragment_id()[..],
        blake3::derive_key("gsp/v0/fragment-id", &root)[..16]
    );
    assert_eq!(
        *p.relay_token(),
        blake3::derive_key("gsp/v0/relay-token", &root)
    );
    assert_eq!(CTX_FRAGMENT_KEY, "gsp/v0/fragment-key");
    assert_eq!(CTX_FRAGMENT_ID, "gsp/v0/fragment-id");
    assert_eq!(CTX_RELAY_TOKEN, "gsp/v0/relay-token");
    assert_eq!(FRAGMENT_ID_LEN, 16);

    // The three values are unrelated to each other and to the root.
    let all = [
        p.fragment_key_bytes().to_vec(),
        p.relay_token().to_vec(),
        blake3::derive_key("gsp/v0/fragment-id", &root).to_vec(),
        root.to_vec(),
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
    // A different root gives a different everything.
    let q = Pairing::from_root([8u8; 32]);
    assert_ne!(p.fragment_id(), q.fragment_id());
    assert_ne!(*p.relay_token(), *q.relay_token());
    assert_ne!(*p.fragment_key_bytes(), *q.fragment_key_bytes());
}

/// Pinned outputs for root = 32 bytes of 0x07, so a change in derivation is
/// noticed and a second implementation has something to compare with. They
/// were produced by this code (BLAKE3 `derive_key` of the `blake3` crate) and
/// not checked against another implementation.
#[test]
fn pinned_vector() {
    let p = Pairing::from_root([7u8; 32]);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("fragment_key = {}", hex(&*p.fragment_key_bytes()));
    println!("fragment_id  = {}", hex(&p.fragment_id()));
    println!("relay_token  = {}", hex(&*p.relay_token()));
    println!("text         = {}", *p.to_text());
    assert_eq!(
        &*p.to_text(),
        "gsp0-BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
    );
    assert_eq!(hex(&p.fragment_id()), PINNED_FRAGMENT_ID);
    assert_eq!(hex(&*p.fragment_key_bytes()), PINNED_FRAGMENT_KEY);
    assert_eq!(hex(&*p.relay_token()), PINNED_RELAY_TOKEN);
}

const PINNED_FRAGMENT_ID: &str = "02adb8e7fdb9d8a9b971b752e5ea9870";
const PINNED_FRAGMENT_KEY: &str =
    "105866ba709f822a170d7a713d99618c543d007eb882f550ff8278067df5a35d";
const PINNED_RELAY_TOKEN: &str = "def205a5bfcf8602184f02f0aa967aabe961efa850276eaed605f5c6bea18993";

#[test]
fn text_form_round_trips() {
    for root in [[0u8; 32], [0xff; 32], [7u8; 32], {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        r
    }] {
        let p = Pairing::from_root(root);
        let text = p.to_text();
        assert!(text.starts_with("gsp0-"));
        assert_eq!(text.len(), 5 + 43);
        assert!(!text.contains('='));
        assert!(
            text[5..]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_eq!(Pairing::parse(&text).unwrap().root(), &root);
    }
    assert_eq!(
        &*Pairing::from_root([0u8; 32]).to_text(),
        "gsp0-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(
        &*Pairing::from_root([0xff; 32]).to_text(),
        "gsp0-__________________________________________8"
    );
}

#[test]
fn base64url_matches_rfc4648_vectors() {
    // RFC 4648 section 10, without padding.
    for (input, want) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64url(input.as_bytes()), want);
    }
    // The two characters that differ from standard base64.
    assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
}

#[test]
fn parsing_is_strict() {
    let good = Pairing::from_root([7u8; 32]).to_text().to_string();
    assert!(Pairing::parse(&good).is_ok());
    let body = &good[5..];

    // Prefix: exact, case-sensitive, nothing before it.
    for bad in [
        body.to_string(),
        format!("GSP0-{body}"),
        format!("gsp1-{body}"),
        format!("gsp0{body}"),
        format!(" gsp0-{body}"),
        format!("gsp0_{body}"),
        String::new(),
    ] {
        assert_eq!(Pairing::parse(&bad).unwrap_err(), PairingError::Prefix);
    }
    // Length: exactly 43 characters.
    for bad in [
        "gsp0-".to_string(),
        format!("gsp0-{}", &body[..42]),
        format!("gsp0-{body}A"),
        format!("gsp0-{body}="),
        format!("gsp0-{body} "),
        format!("gsp0-{body}\n"),
    ] {
        assert_eq!(Pairing::parse(&bad).unwrap_err(), PairingError::Length);
    }
    // Alphabet: no padding, no standard-base64 characters, no whitespace,
    // no non-ASCII, at any position.
    for c in ['=', '+', '/', ' ', '\n', '.', '\0', '~'] {
        for pos in [0, 20, 42] {
            let mut b: Vec<char> = body.chars().collect();
            b[pos] = c;
            let bad = format!("gsp0-{}", b.into_iter().collect::<String>());
            assert_eq!(
                Pairing::parse(&bad).unwrap_err(),
                PairingError::Alphabet,
                "{c:?} at {pos}"
            );
        }
    }
    // A two-byte character keeps the byte length at 43 only by replacing two.
    let multi = format!("gsp0-{}é", &body[..41]);
    assert_eq!(multi.len(), 48);
    assert_eq!(Pairing::parse(&multi).unwrap_err(), PairingError::Alphabet);

    // Canonical: the last character carries 4 bits of data and 2 unused
    // bits, which must be zero. Only 16 of the 64 characters are allowed
    // there, so exactly one text decodes to each secret.
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut ok = 0;
    for (i, c) in alphabet.chars().enumerate() {
        let t = format!("gsp0-{}{c}", &body[..42]);
        match Pairing::parse(&t) {
            Ok(p) => {
                ok += 1;
                assert_eq!(i % 4, 0);
                assert_eq!(&*p.to_text(), &t);
            }
            Err(e) => {
                assert_eq!(e, PairingError::NonCanonical);
                assert_ne!(i % 4, 0);
            }
        }
    }
    assert_eq!(ok, 16);
}

#[test]
fn debug_does_not_print_the_secret() {
    let p = Pairing::from_root([7u8; 32]);
    let dbg = format!("{p:?}");
    assert!(!dbg.contains("7, 7"));
    assert!(!dbg.contains(&p.to_text()[5..]));
    assert!(dbg.contains("secret"));
}
