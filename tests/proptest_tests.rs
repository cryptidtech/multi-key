// SPDX-License-Identifier: Apache-2.0
//! Property-based tests for multi-key
#![cfg(feature = "curve25519")]

use multi_codec::Codec;
use multi_key::Builder;
use proptest::prelude::*;

/// Property: Multikey encoding and decoding should roundtrip
#[cfg(feature = "secp256k1")]
#[test]
fn test_multikey_roundtrip() {
    use multi_key::Multikey;
    use multi_trait::TryDecodeFrom;

    proptest!(|(_unit in 0..1u8)| {
        let mut rng = rand::rng();
        for codec in [Codec::Ed25519Priv, Codec::Secp256K1Priv] {
            let mk1 = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .try_build()
                .unwrap();
            let bytes = Vec::<u8>::from(&mk1);
            let (mk2, remaining) = Multikey::try_decode_from(&bytes).unwrap();

            prop_assert_eq!(&mk1, &mk2);
            prop_assert!(remaining.is_empty());
        }
    });
}

/// Property: Clone produces equal value
#[test]
fn test_clone_equality() {
    proptest!(|(_unit in 0..1u8)| {
        let mut rng = rand::rng();
        if let Ok(builder) = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            && let Ok(mk1) = builder.try_build()
        {
            let mk2 = mk1.clone();
            prop_assert_eq!(&mk1, &mk2);
        }
    });
}
