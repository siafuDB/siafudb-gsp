//! Pairing: derivation with the exact context strings of SYNC-V0 section 2,
//! and the strict text form.
use gsp_sync::*;

const ORIGIN: &str = "https://relay.example";

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
    // The relay token binds the relay: root followed by the canonical origin.
    let mut material = root.to_vec();
    material.extend_from_slice(b"https://relay.example");
    assert_eq!(
        *p.relay_token(ORIGIN).unwrap(),
        blake3::derive_key("gsp/v0/relay-token", &material)
    );
    assert_eq!(CTX_FRAGMENT_KEY, "gsp/v0/fragment-key");
    assert_eq!(CTX_FRAGMENT_ID, "gsp/v0/fragment-id");
    assert_eq!(CTX_RELAY_TOKEN, "gsp/v0/relay-token");
    assert_eq!(FRAGMENT_ID_LEN, 16);

    // The three values are unrelated to each other and to the root.
    let all = [
        p.fragment_key_bytes().to_vec(),
        p.relay_token(ORIGIN).unwrap().to_vec(),
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
    assert_ne!(
        *p.relay_token(ORIGIN).unwrap(),
        *q.relay_token(ORIGIN).unwrap()
    );
    assert_ne!(*p.fragment_key_bytes(), *q.fragment_key_bytes());
}

/// Pinned outputs for root = 32 bytes of 0x07 and the relay origin
/// `https://relay.example`, so a change in derivation is
/// noticed and a second implementation has something to compare with. They
/// were produced by this code (BLAKE3 `derive_key` of the `blake3` crate) and
/// not checked against another implementation.
#[test]
fn pinned_vector() {
    let p = Pairing::from_root([7u8; 32]);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("fragment_key = {}", hex(&*p.fragment_key_bytes()));
    println!("fragment_id  = {}", hex(&p.fragment_id()));
    println!(
        "relay_token(https://relay.example) = {}",
        hex(&*p.relay_token(ORIGIN).unwrap())
    );
    println!("text         = {}", *p.to_text());
    assert_eq!(
        &*p.to_text(),
        "gsp0-BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
    );
    assert_eq!(hex(&p.fragment_id()), PINNED_FRAGMENT_ID);
    assert_eq!(hex(&*p.fragment_key_bytes()), PINNED_FRAGMENT_KEY);
    assert_eq!(hex(&*p.relay_token(ORIGIN).unwrap()), PINNED_RELAY_TOKEN);
}

const PINNED_FRAGMENT_ID: &str = "02adb8e7fdb9d8a9b971b752e5ea9870";
const PINNED_FRAGMENT_KEY: &str =
    "105866ba709f822a170d7a713d99618c543d007eb882f550ff8278067df5a35d";
const PINNED_RELAY_TOKEN: &str = "013b0083a98a206f11630a07c1a035bb37a2a2ce6c14120c1b70668f487a02ba";

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

#[test]
fn relay_token_is_different_for_every_relay() {
    let p = Pairing::from_root([7u8; 32]);
    let token = |o: &str| p.relay_token(o).unwrap().to_vec();
    let a = token("https://relay.example");
    // Another host, scheme or port is another relay.
    for other in [
        "https://relay.example.org",
        "http://relay.example",
        "https://relay.example:8443",
        "https://relay2.example",
        "https://[2001:db8::1]",
    ] {
        assert_ne!(token(other), a, "{other}");
    }
    // Spellings of the same origin give the same token.
    for same in [
        "https://relay.example/",
        "HTTPS://Relay.Example",
        "https://relay.example:443",
        "https://RELAY.EXAMPLE:0443/",
    ] {
        assert_eq!(token(same), a, "{same}");
    }
    // The old, unbound token (derived from the root alone) is not any
    // relay's token.
    assert_ne!(
        a,
        blake3::derive_key("gsp/v0/relay-token", &[7u8; 32]).to_vec()
    );
    // Through a replica it is the same value.
    let r = Replica::create([7; 32], [1; 32], [2; 24], Config::default()).unwrap();
    assert_eq!(r.relay_token("https://relay.example").unwrap().to_vec(), a);
    assert_eq!(r.relay_token("relay.example"), Err(OriginError::Scheme));
}

#[test]
fn canonical_origin_normalises_and_rejects() {
    for (input, want) in [
        ("https://relay.example", "https://relay.example"),
        ("https://relay.example/", "https://relay.example"),
        ("HTTPS://Relay.EXAMPLE", "https://relay.example"),
        ("https://relay.example:443", "https://relay.example"),
        ("http://relay.example:80", "http://relay.example"),
        ("http://relay.example:443", "http://relay.example:443"),
        ("https://relay.example:80", "https://relay.example:80"),
        ("https://relay.example:08443", "https://relay.example:8443"),
        ("http://localhost:8787", "http://localhost:8787"),
        ("http://127.0.0.1:8787/", "http://127.0.0.1:8787"),
        (
            "https://xn--bcher-kva.example",
            "https://xn--bcher-kva.example",
        ),
        ("https://[2001:DB8::1]", "https://[2001:db8::1]"),
        ("https://[2001:db8::1]:443", "https://[2001:db8::1]"),
        ("http://[::1]:8787", "http://[::1]:8787"),
        (
            "https://[::ffff:192.0.2.1]:65535",
            "https://[::ffff:192.0.2.1]:65535",
        ),
    ] {
        assert_eq!(canonical_origin(input).as_deref(), Ok(want), "{input}");
        // Canonical form is a fixed point.
        assert_eq!(canonical_origin(want).as_deref(), Ok(want));
    }
    for (input, why) in [
        ("", OriginError::Scheme),
        ("relay.example", OriginError::Scheme),
        ("//relay.example", OriginError::Scheme),
        ("ftp://relay.example", OriginError::Scheme),
        ("wss://relay.example", OriginError::Scheme),
        ("https:/relay.example", OriginError::Scheme),
        (" https://relay.example", OriginError::Scheme),
        ("https://", OriginError::Host),
        ("https:///", OriginError::Host),
        ("https://:443", OriginError::Host),
        ("https://relay example", OriginError::Host),
        ("https://relay.example ", OriginError::Host),
        ("https://relay_example", OriginError::Host),
        ("https://bücher.example", OriginError::Host),
        ("https://relay.example\\n", OriginError::Host),
        ("https://[2001:db8::1", OriginError::Host),
        ("https://[]", OriginError::Host),
        ("https://[relay.example]", OriginError::Host),
        ("https://[::1]x", OriginError::Host),
        ("https://[::g]", OriginError::Host),
        ("https://relay.example:", OriginError::Port),
        ("https://relay.example:0", OriginError::Port),
        ("https://relay.example:65536", OriginError::Port),
        ("https://relay.example:8o", OriginError::Port),
        ("https://relay.example:-1", OriginError::Port),
        ("https://relay.example:+80", OriginError::Port),
        ("https://relay.example:1:2", OriginError::Port),
        ("https://[::1]:", OriginError::Port),
        (
            "https://relay.example:99999999999999999999",
            OriginError::Port,
        ),
        ("https://relay.example/v0", OriginError::Extra),
        ("https://relay.example//", OriginError::Extra),
        ("https://relay.example/v0/", OriginError::Extra),
        ("https://relay.example?x=1", OriginError::Extra),
        ("https://relay.example#frag", OriginError::Extra),
        ("https://user@relay.example", OriginError::Extra),
        ("https://user:pw@relay.example", OriginError::Extra),
    ] {
        assert_eq!(canonical_origin(input), Err(why), "{input:?}");
    }
}
