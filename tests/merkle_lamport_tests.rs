// SPDX-License-Identifier: Apache-2.0
//! End-to-end merkle-tree Lamport flow: keygen, `sign_advance`, verify,
//! threshold split, share-sign, multi-sig accumulate, combine, verify.

#![cfg(feature = "lamport")]
#![allow(clippy::uninlined_format_args)]

use multi_codec::Codec;
use multi_key::{Builder, Multikey, Views as _};
use multi_sig::{Multisig, Views as _};

#[test]
fn test_merkle_sign_advance_and_verify() {
    let mut rng = rand::rng();
    let sk =
        Builder::new_from_random_bytes_with_depth(Codec::LamportMerkleSha2256Priv, 1, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
    let pk = sk.conv_view().unwrap().to_public_key().unwrap();

    let sv = sk.merkle_state_view().unwrap();
    assert_eq!(sv.depth().unwrap(), 1);
    assert_eq!(sv.capacity().unwrap(), 2);
    assert_eq!(sv.remaining_signatures().unwrap(), 2);

    let msg = b"integration merkle message";
    let (ms, advanced) = sk
        .sign_view()
        .unwrap()
        .sign_advance(msg, true, None)
        .unwrap();

    // depth attribute travels on the signature
    assert_eq!(ms.depth(), Some(1));

    pk.verify_view().unwrap().verify(&ms, Some(msg)).unwrap();

    // advanced key must be persisted and reflect the consumed leaf
    let av = advanced.merkle_state_view().unwrap();
    assert_eq!(av.next_index().unwrap(), 1);
    assert_eq!(av.remaining_signatures().unwrap(), 1);

    // roundtrip the advanced key through wire encoding
    let bytes: Vec<u8> = advanced.clone().into();
    let restored = Multikey::try_from(bytes.as_slice()).unwrap();
    assert_eq!(restored, advanced);
    let rv = restored.merkle_state_view().unwrap();
    assert_eq!(rv.next_index().unwrap(), 1);
}

#[test]
fn test_merkle_threshold_split_sign_combine_verify() {
    let mut rng = rand::rng();
    let sk =
        Builder::new_from_random_bytes_with_depth(Codec::LamportMerkleSha3256Priv, 1, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
    let pk = sk.conv_view().unwrap().to_public_key().unwrap();

    // split 2-of-3
    let shares = sk.threshold_view().unwrap().split(2, 3).unwrap();
    assert_eq!(shares.len(), 3);

    let msg = b"threshold integration message";

    // two participants sign (detached) to signature shares
    let sig_shares: Vec<Multisig> = shares
        .iter()
        .take(2)
        .map(|share| {
            let (ms, _adv) = share
                .sign_view()
                .unwrap()
                .sign_advance(msg, false, None)
                .unwrap();
            ms
        })
        .collect();

    // accumulate and combine on the multisig
    let mut acc = multi_sig::Builder::new(Codec::LamportMerkleSha3256Sig)
        .with_message_bytes(&msg)
        .try_build()
        .unwrap();
    for share in &sig_shares {
        let next = acc.threshold_view().unwrap().add_share(share).unwrap();
        acc = next;
    }
    assert_eq!(acc.depth(), Some(1));

    let combined = acc.threshold_view().unwrap().combine().unwrap();
    assert_eq!(combined.depth(), Some(1));

    // verify under the tree-root public key
    pk.verify_view()
        .unwrap()
        .verify(&combined, Some(msg))
        .unwrap();
}

#[test]
fn test_merkle_builder_depth_validation() {
    let mut rng = rand::rng();
    for bad in [0u8, 4, 255] {
        assert!(
            Builder::new_from_random_bytes_with_depth(
                Codec::LamportMerkleSha2256Priv,
                bad,
                &mut rng
            )
            .is_err(),
            "depth {bad} must be rejected"
        );
    }
}
