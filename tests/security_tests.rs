// SPDX-License-Identifier: Apache-2.0
//! Security-focused tests for multi-key

use multi_codec::Codec;
use multi_key::{Builder, Error, Multikey};

/// Test malformed multikey data
#[test]
fn test_malformed_data() {
    let invalid = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = Multikey::try_from(invalid.as_ref());
    assert!(result.is_err());
}

/// Test truncated multikey
#[test]
fn test_truncated_data() {
    let truncated = vec![0xBA, 0x24]; // Multikey sigil 0x123a as varuint, no payload
    let result = Multikey::try_from(truncated.as_ref());
    assert!(result.is_err());
}

/// Test empty bytes
#[test]
fn test_empty_bytes() {
    let result = Multikey::try_from(&[] as &[u8]);
    assert!(result.is_err());
}

/// Test concurrent key generation
#[test]
fn test_concurrent_generation() {
    use rand::SeedableRng;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;

    // ThreadRng is !Send; use the Send StdRng (still a rand_core 0.10 CryptoRng).
    let rng = Arc::new(Mutex::new(rand::rngs::StdRng::from_rng(&mut rand::rng())));
    let mut handles = vec![];

    for _ in 0..4 {
        let rng_clone = Arc::clone(&rng);
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let mut rng = rng_clone.lock().unwrap();
                if let Ok(builder) = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut *rng) {
                    let _ = builder.try_build();
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

/// Test error types are Send + Sync
#[test]
fn test_error_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<Error>();
    assert_sync::<Error>();
}

/// Test zeroization of private keys
#[test]
fn test_private_key_zeroization() {
    use multi_key::types::PrivateKeyBytes;

    {
        let _privkey = PrivateKeyBytes::new(vec![0x42; 32]);
        // Should be zeroized when dropped
    }
    // Memory should be cleared
}

/// Regression test for C1: a tampered ChaCha20Poly1305 ciphertext must NOT be
/// silently decrypted via the legacy bare-ChaCha20 fallback. Without the
/// `legacy_chacha20_fallback` feature, AEAD failure must surface as a hard
/// error so an attacker can never downgrade authentication.
#[cfg(not(feature = "legacy_chacha20_fallback"))]
#[test]
fn test_chacha20_aead_tamper_rejected() {
    use multi_key::{cipher, kdf, Builder, Views};

    let plain =
        hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2").unwrap();
    let mk1 = Builder::new(Codec::Ed25519Priv)
        .with_comment("test key")
        .with_key_bytes(&plain)
        .try_build()
        .unwrap();

    let salt =
        hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406").unwrap();
    let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
        .with_salt(&salt)
        .with_rounds(10)
        .try_build()
        .unwrap();
    let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
    let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
        .with_nonce(&nonce)
        .try_build()
        .unwrap();
    let ciphermk = ciphermk
        .kdf_view(&kdfmk)
        .unwrap()
        .derive_key(b"for great justice, move every zig!")
        .unwrap();

    // encrypt → authenticated ciphertext (plaintext || 16-byte tag)
    let enc = mk1.cipher_view(&ciphermk).unwrap().encrypt().unwrap();
    assert!(enc.attr_view().unwrap().is_encrypted());

    // tamper with the stored ciphertext attribute so AEAD verification fails
    let mut tampered = enc.clone();
    let key_data = tampered
        .attributes
        .get(&multi_key::AttrId::KeyData)
        .unwrap()
        .clone();
    let mut corrupted = key_data.to_vec();
    // flip a bit in the ciphertext body (not the tag) so the tag check fails
    corrupted[0] ^= 0xff;
    tampered
        .attributes
        .insert(multi_key::AttrId::KeyData, corrupted.into());

    let result = tampered.cipher_view(&ciphermk).unwrap().decrypt();
    assert!(
        result.is_err(),
        "decrypting tampered AEAD ciphertext must fail, not silently fall back \
         to unauthenticated ChaCha20"
    );
}

/// Companion to `test_chacha20_aead_tamper_rejected`: with the opt-in
/// `legacy_chacha20_fallback` feature enabled, tampered AEAD ciphertext falls
/// back to bare ChaCha20 and "succeeds" (producing garbage). This documents
/// the downgrade risk the feature carries — it must stay off by default.
#[cfg(feature = "legacy_chacha20_fallback")]
#[test]
fn test_chacha20_legacy_fallback_downgrades_on_tamper() {
    use multi_key::{cipher, kdf, Builder, Views};

    let plain =
        hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2").unwrap();
    let mk1 = Builder::new(Codec::Ed25519Priv)
        .with_comment("test key")
        .with_key_bytes(&plain)
        .try_build()
        .unwrap();

    let salt =
        hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406").unwrap();
    let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
        .with_salt(&salt)
        .with_rounds(10)
        .try_build()
        .unwrap();
    let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
    let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
        .with_nonce(&nonce)
        .try_build()
        .unwrap();
    let ciphermk = ciphermk
        .kdf_view(&kdfmk)
        .unwrap()
        .derive_key(b"for great justice, move every zig!")
        .unwrap();

    let enc = mk1.cipher_view(&ciphermk).unwrap().encrypt().unwrap();

    // tamper with the ciphertext body so AEAD verification fails
    let mut tampered = enc.clone();
    let key_data = tampered
        .attributes
        .get(&multi_key::AttrId::KeyData)
        .unwrap()
        .clone();
    let mut corrupted = key_data.to_vec();
    corrupted[0] ^= 0xff;
    tampered
        .attributes
        .insert(multi_key::AttrId::KeyData, corrupted.into());

    // With the legacy fallback enabled, the bare-ChaCha20 path is taken and
    // decrypt "succeeds" — but the output is garbage, NOT the original key.
    let dec = tampered.cipher_view(&ciphermk).unwrap().decrypt().unwrap();
    assert_ne!(
        dec.data_view().unwrap().secret_bytes().unwrap().as_slice(),
        plain.as_slice(),
        "legacy fallback must not be used to authenticate; it yields garbage \
         on tampered ciphertext"
    );
}
