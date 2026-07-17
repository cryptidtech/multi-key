// SPDX-License-Identifier: Apache-2.0
//! Edge case tests for multi-key
#![allow(clippy::explicit_iter_loop, clippy::uninlined_format_args)]

use multi_codec::Codec;
use multi_key::{Builder, KEY_CODECS, Multikey};
use multi_trait::Null;

/// Test null multikey
#[test]
fn test_null_multikey() {
    let null_mk = Multikey::null();
    assert!(null_mk.is_null());
    assert_eq!(null_mk, Multikey::default());
}

/// Test all supported key codecs
#[test]
fn test_all_key_codecs() {
    let mut rng = rand::rng();
    for &codec in KEY_CODECS.iter() {
        let result = Builder::new_from_random_bytes(codec, &mut rng);
        // Should be able to create builder for all supported codecs
        assert!(result.is_ok(), "Failed for {:?}", codec);
    }
}

/// Test Clone trait
#[test]
fn test_clone() {
    let mut rng = rand::rng();
    if let Ok(builder) = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng) {
        if let Ok(mk1) = builder.try_build() {
            let mk2 = mk1.clone();
            assert_eq!(mk1, mk2);
        }
    }
}

/// Test Send and Sync
#[test]
fn test_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<Multikey>();
    assert_sync::<Multikey>();
    assert_send::<Builder>();
}
