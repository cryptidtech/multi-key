// SPDX-License-Identifier: Apache-2.0
//! Property-based tests for multi-key

use multi_codec::Codec;
use multi_key::{Builder, KEY_CODECS, Multikey};
use multi_trait::TryDecodeFrom;
use proptest::prelude::*;

/// Property: Multikey encoding and decoding should roundtrip
#[test]
fn test_multikey_roundtrip() {
    proptest!(|(_unit in 0..1u8)| {
        let mut rng = rand::rng();
        for &codec in KEY_CODECS.iter().take(2) {
            if let Ok(mk1) = Builder::new_from_random_bytes(codec, &mut rng) {
                if let Ok(mk1) = mk1.try_build() {
                    let bytes: Vec<u8> = mk1.clone().into();
                    let (mk2, remaining) = Multikey::try_decode_from(&bytes).unwrap();

                    prop_assert_eq!(&mk1, &mk2);
                    prop_assert!(remaining.is_empty());
                }
            }
        }
    });
}

/// Property: Clone produces equal value
#[test]
fn test_clone_equality() {
    proptest!(|(_unit in 0..1u8)| {
        let mut rng = rand::rng();
        if let Ok(builder) = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng) {
            if let Ok(mk1) = builder.try_build() {
                let mk2 = mk1.clone();
                prop_assert_eq!(&mk1, &mk2);
            }
        }
    });
}
