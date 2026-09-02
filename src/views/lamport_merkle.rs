// SPDX-License-Identifier: Apache-2.0
//! Merkle-tree Lamport multikey view (`lamport_signature_plus` 0.5.0 `Mt*` API).
//!
//! ⚠️ The tree holds `2^depth` ONE-TIME leaves (depth 1, 2, or 3): every leaf
//! is a one-time Lamport key. [`SignView::sign_advance`] consumes one leaf and
//! returns the advanced key state; the caller MUST persist it. Restoring an
//! older copy of the key state can reuse a leaf and destroy the tree's
//! security.
//!
//! Depth discipline: every Multikey/Multisig this view builds carries the
//! [`AttrId::Depth`] attribute (one raw byte). Every read cross-checks that
//! byte against the depth byte embedded in the `Mt*` wire data and fails with
//! [`AttributesError::DepthMismatch`] on a mismatch. The `Mt*` wire layouts:
//! `MtVerifyingKey`/`MtSigningKey`/`MtSigningKeyShare` embed depth at byte 0
//! and 1 respectively (`[depth, root]`, `[version, depth, next_index, …]`);
//! `MtSignature`/`MtSignatureShare` embed depth at byte 0 (`[depth, index, …]`).

use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, MerkleStateView,
    Multikey, SignView, ThresholdView, VerifyView,
    error::{AttributesError, ConversionsError, SignError, ThresholdError, VerifyError},
    views::Views,
    views::lamport::{
        Blake2b512Digest, Blake2s256Digest, Blake3_256Digest, Sha2_256Digest, Sha2_384Digest,
        Sha2_512Digest, Sha3_256Digest, Sha3_384Digest, Sha3_512Digest, Shake128Digest,
        Shake256Digest,
    },
};
use lamport_signature_plus::{
    LamportDigest, MtSignature, MtSigningKey, MtSigningKeyShare, MtVerifyingKey, generate_mt_keys,
};
use multi_codec::Codec;
use multi_hash::{Multihash, mh};
use multi_sig::{AttrId as MsAttrId, Views as _, ms};
use zeroize::Zeroizing;

/// Mt state wire format version byte (lamport_signature_plus 0.5.0).
const MT_STATE_FORMAT_VERSION: u8 = 1;

// ---- wrappers over lamport_signature_plus::merkle ----

mod merkle_wrapper {
    use super::{
        Blake2b512Digest, Blake2s256Digest, Blake3_256Digest, LamportDigest, MtSignature,
        MtSigningKey, MtSigningKeyShare, MtVerifyingKey, Sha2_256Digest, Sha2_384Digest,
        Sha2_512Digest, Sha3_256Digest, Sha3_384Digest, Sha3_512Digest, Shake128Digest,
        Shake256Digest, Zeroizing, generate_mt_keys,
    };

    pub fn keypair<T: LamportDigest>(depth: u8) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
        let (sk, pk) = generate_mt_keys::<T, _>(depth, rand::rng()).map_err(|e| e.to_string())?;
        Ok((pk.to_bytes(), Zeroizing::new(sk.to_bytes())))
    }

    pub fn public_from_private<T: LamportDigest>(
        secret_key_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let sk = MtSigningKey::<T>::from_bytes(secret_key_bytes).map_err(|e| e.to_string())?;
        Ok(MtVerifyingKey::from(&sk).to_bytes())
    }

    /// Sign at the next leaf. Returns the MtSignature bytes and the advanced
    /// state bytes (the caller must persist them).
    pub fn sign<T: LamportDigest>(
        secret_key_bytes: &[u8],
        msg: &[u8],
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
        let mut sk = MtSigningKey::<T>::from_bytes(secret_key_bytes).map_err(|e| e.to_string())?;
        let sig = sk.sign(msg).map_err(|e| e.to_string())?;
        let sig_bytes = sig.to_bytes();
        let advanced = Zeroizing::new(sk.to_bytes());
        Ok((sig_bytes, advanced))
    }

    pub fn verify<T: LamportDigest>(
        public_key_bytes: &[u8],
        signature_bytes: &[u8],
        msg: &[u8],
    ) -> Result<(), String> {
        let pk = MtVerifyingKey::<T>::from_bytes(public_key_bytes).map_err(|e| e.to_string())?;
        let sig = MtSignature::<T>::from_bytes(signature_bytes).map_err(|e| e.to_string())?;
        pk.verify(&sig, msg).map_err(|e| e.to_string())
    }

    pub fn split<T: LamportDigest>(
        secret_key_bytes: &[u8],
        threshold: usize,
        limit: usize,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, String> {
        let sk = MtSigningKey::<T>::from_bytes(secret_key_bytes).map_err(|e| e.to_string())?;
        let shares = sk
            .split(threshold, limit, rand::rng())
            .map_err(|e| e.to_string())?;
        Ok(shares
            .iter()
            .map(|s| Zeroizing::new(s.to_bytes()))
            .collect())
    }

    pub fn share_sign<T: LamportDigest>(share_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        let mut share =
            MtSigningKeyShare::<T>::from_bytes(share_bytes).map_err(|e| e.to_string())?;
        Ok(share.sign(msg).map_err(|e| e.to_string())?.to_bytes())
    }

    macro_rules! variant {
        ($digest:ty, $kp:ident, $pfp:ident, $sign:ident, $verify:ident, $split:ident, $share_sign:ident) => {
            pub fn $kp(depth: u8) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
                keypair::<$digest>(depth)
            }
            pub fn $pfp(s: &[u8]) -> Result<Vec<u8>, String> {
                public_from_private::<$digest>(s)
            }
            pub fn $sign(s: &[u8], m: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
                sign::<$digest>(s, m)
            }
            pub fn $verify(p: &[u8], s: &[u8], m: &[u8]) -> Result<(), String> {
                verify::<$digest>(p, s, m)
            }
            pub fn $split(s: &[u8], t: usize, l: usize) -> Result<Vec<Zeroizing<Vec<u8>>>, String> {
                split::<$digest>(s, t, l)
            }
            pub fn $share_sign(s: &[u8], m: &[u8]) -> Result<Vec<u8>, String> {
                share_sign::<$digest>(s, m)
            }
        };
    }

    variant!(
        Sha3_256Digest,
        keypair_256,
        public_from_private_256,
        sign_256,
        verify_256,
        split_256,
        share_sign_256
    );
    variant!(
        Sha3_384Digest,
        keypair_384,
        public_from_private_384,
        sign_384,
        verify_384,
        split_384,
        share_sign_384
    );
    variant!(
        Sha3_512Digest,
        keypair_512,
        public_from_private_512,
        sign_512,
        verify_512,
        split_512,
        share_sign_512
    );
    variant!(
        Sha2_256Digest,
        keypair_sha2_256,
        public_from_private_sha2_256,
        sign_sha2_256,
        verify_sha2_256,
        split_sha2_256,
        share_sign_sha2_256
    );
    variant!(
        Sha2_384Digest,
        keypair_sha2_384,
        public_from_private_sha2_384,
        sign_sha2_384,
        verify_sha2_384,
        split_sha2_384,
        share_sign_sha2_384
    );
    variant!(
        Sha2_512Digest,
        keypair_sha2_512,
        public_from_private_sha2_512,
        sign_sha2_512,
        verify_sha2_512,
        split_sha2_512,
        share_sign_sha2_512
    );
    variant!(
        Blake2b512Digest,
        keypair_blake2b_512,
        public_from_private_blake2b_512,
        sign_blake2b_512,
        verify_blake2b_512,
        split_blake2b_512,
        share_sign_blake2b_512
    );
    variant!(
        Blake2s256Digest,
        keypair_blake2s_256,
        public_from_private_blake2s_256,
        sign_blake2s_256,
        verify_blake2s_256,
        split_blake2s_256,
        share_sign_blake2s_256
    );
    variant!(
        Blake3_256Digest,
        keypair_blake3_256,
        public_from_private_blake3_256,
        sign_blake3_256,
        verify_blake3_256,
        split_blake3_256,
        share_sign_blake3_256
    );
    variant!(
        Shake128Digest,
        keypair_shake_128,
        public_from_private_shake_128,
        sign_shake_128,
        verify_shake_128,
        split_shake_128,
        share_sign_shake_128
    );
    variant!(
        Shake256Digest,
        keypair_shake_256,
        public_from_private_shake_256,
        sign_shake_256,
        verify_shake_256,
        split_shake_256,
        share_sign_shake_256
    );
}

fn is_merkle_priv(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::LamportMerkleSha3256Priv
            | Codec::LamportMerkleSha3384Priv
            | Codec::LamportMerkleSha3512Priv
            | Codec::LamportMerkleSha2256Priv
            | Codec::LamportMerkleSha2384Priv
            | Codec::LamportMerkleSha2512Priv
            | Codec::LamportMerkleBlake2B512Priv
            | Codec::LamportMerkleBlake2S256Priv
            | Codec::LamportMerkleBlake3256Priv
            | Codec::LamportMerkleShake128Priv
            | Codec::LamportMerkleShake256Priv
    )
}

fn is_merkle_pub(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::LamportMerkleSha3256Pub
            | Codec::LamportMerkleSha3384Pub
            | Codec::LamportMerkleSha3512Pub
            | Codec::LamportMerkleSha2256Pub
            | Codec::LamportMerkleSha2384Pub
            | Codec::LamportMerkleSha2512Pub
            | Codec::LamportMerkleBlake2B512Pub
            | Codec::LamportMerkleBlake2S256Pub
            | Codec::LamportMerkleBlake3256Pub
            | Codec::LamportMerkleShake128Pub
            | Codec::LamportMerkleShake256Pub
    )
}

fn is_merkle_priv_share(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::LamportMerkleSha3256PrivShare
            | Codec::LamportMerkleSha3384PrivShare
            | Codec::LamportMerkleSha3512PrivShare
            | Codec::LamportMerkleSha2256PrivShare
            | Codec::LamportMerkleSha2384PrivShare
            | Codec::LamportMerkleSha2512PrivShare
            | Codec::LamportMerkleBlake2B512PrivShare
            | Codec::LamportMerkleBlake2S256PrivShare
            | Codec::LamportMerkleBlake3256PrivShare
            | Codec::LamportMerkleShake128PrivShare
            | Codec::LamportMerkleShake256PrivShare
    )
}

fn public_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportMerkleSha3256Priv => Ok(Codec::LamportMerkleSha3256Pub),
        Codec::LamportMerkleSha3384Priv => Ok(Codec::LamportMerkleSha3384Pub),
        Codec::LamportMerkleSha3512Priv => Ok(Codec::LamportMerkleSha3512Pub),
        Codec::LamportMerkleSha2256Priv => Ok(Codec::LamportMerkleSha2256Pub),
        Codec::LamportMerkleSha2384Priv => Ok(Codec::LamportMerkleSha2384Pub),
        Codec::LamportMerkleSha2512Priv => Ok(Codec::LamportMerkleSha2512Pub),
        Codec::LamportMerkleBlake2B512Priv => Ok(Codec::LamportMerkleBlake2B512Pub),
        Codec::LamportMerkleBlake2S256Priv => Ok(Codec::LamportMerkleBlake2S256Pub),
        Codec::LamportMerkleBlake3256Priv => Ok(Codec::LamportMerkleBlake3256Pub),
        Codec::LamportMerkleShake128Priv => Ok(Codec::LamportMerkleShake128Pub),
        Codec::LamportMerkleShake256Priv => Ok(Codec::LamportMerkleShake256Pub),
        _ => Err(
            ConversionsError::SecretKeyFailure("not a merkle-Lamport private key".into()).into(),
        ),
    }
}

fn sig_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportMerkleSha3256Priv => Ok(Codec::LamportMerkleSha3256Sig),
        Codec::LamportMerkleSha3384Priv => Ok(Codec::LamportMerkleSha3384Sig),
        Codec::LamportMerkleSha3512Priv => Ok(Codec::LamportMerkleSha3512Sig),
        Codec::LamportMerkleSha2256Priv => Ok(Codec::LamportMerkleSha2256Sig),
        Codec::LamportMerkleSha2384Priv => Ok(Codec::LamportMerkleSha2384Sig),
        Codec::LamportMerkleSha2512Priv => Ok(Codec::LamportMerkleSha2512Sig),
        Codec::LamportMerkleBlake2B512Priv => Ok(Codec::LamportMerkleBlake2B512Sig),
        Codec::LamportMerkleBlake2S256Priv => Ok(Codec::LamportMerkleBlake2S256Sig),
        Codec::LamportMerkleBlake3256Priv => Ok(Codec::LamportMerkleBlake3256Sig),
        Codec::LamportMerkleShake128Priv => Ok(Codec::LamportMerkleShake128Sig),
        Codec::LamportMerkleShake256Priv => Ok(Codec::LamportMerkleShake256Sig),
        _ => Err(SignError::NotSigningKey.into()),
    }
}

fn priv_share_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportMerkleSha3256Priv => Ok(Codec::LamportMerkleSha3256PrivShare),
        Codec::LamportMerkleSha3384Priv => Ok(Codec::LamportMerkleSha3384PrivShare),
        Codec::LamportMerkleSha3512Priv => Ok(Codec::LamportMerkleSha3512PrivShare),
        Codec::LamportMerkleSha2256Priv => Ok(Codec::LamportMerkleSha2256PrivShare),
        Codec::LamportMerkleSha2384Priv => Ok(Codec::LamportMerkleSha2384PrivShare),
        Codec::LamportMerkleSha2512Priv => Ok(Codec::LamportMerkleSha2512PrivShare),
        Codec::LamportMerkleBlake2B512Priv => Ok(Codec::LamportMerkleBlake2B512PrivShare),
        Codec::LamportMerkleBlake2S256Priv => Ok(Codec::LamportMerkleBlake2S256PrivShare),
        Codec::LamportMerkleBlake3256Priv => Ok(Codec::LamportMerkleBlake3256PrivShare),
        Codec::LamportMerkleShake128Priv => Ok(Codec::LamportMerkleShake128PrivShare),
        Codec::LamportMerkleShake256Priv => Ok(Codec::LamportMerkleShake256PrivShare),
        _ => Err(ThresholdError::NotASecretKey.into()),
    }
}

fn share_sig_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportMerkleSha3256PrivShare => Ok(Codec::LamportMerkleSha3256SigShare),
        Codec::LamportMerkleSha3384PrivShare => Ok(Codec::LamportMerkleSha3384SigShare),
        Codec::LamportMerkleSha3512PrivShare => Ok(Codec::LamportMerkleSha3512SigShare),
        Codec::LamportMerkleSha2256PrivShare => Ok(Codec::LamportMerkleSha2256SigShare),
        Codec::LamportMerkleSha2384PrivShare => Ok(Codec::LamportMerkleSha2384SigShare),
        Codec::LamportMerkleSha2512PrivShare => Ok(Codec::LamportMerkleSha2512SigShare),
        Codec::LamportMerkleBlake2B512PrivShare => Ok(Codec::LamportMerkleBlake2B512SigShare),
        Codec::LamportMerkleBlake2S256PrivShare => Ok(Codec::LamportMerkleBlake2S256SigShare),
        Codec::LamportMerkleBlake3256PrivShare => Ok(Codec::LamportMerkleBlake3256SigShare),
        Codec::LamportMerkleShake128PrivShare => Ok(Codec::LamportMerkleShake128SigShare),
        Codec::LamportMerkleShake256PrivShare => Ok(Codec::LamportMerkleShake256SigShare),
        _ => Err(SignError::NotSigningKey.into()),
    }
}

/// Validate the depth byte embedded in `Mt*` wire data at the given offset
/// against the depth attribute stamped on the artifact.
/// The depth attribute bytes: `Some(Zeroizing<Vec<u8>>)` on a Multikey,
/// `Option<Vec<u8>>` on a Multisig.
fn depth_attr_value(mk: &Multikey) -> Result<u8, Error> {
    let attr = mk
        .attributes
        .get(&AttrId::Depth)
        .ok_or(AttributesError::MissingThreshold)?;
    if attr.len() != 1 {
        return Err(AttributesError::InvalidAttributeValue(attr.len() as u8).into());
    }
    Ok(attr[0])
}

/// The depth attribute value of a Multisig, if present.
fn multisig_depth(ms: &ms::Multisig) -> Result<u8, Error> {
    let attr = ms
        .attributes
        .get(&MsAttrId::Depth)
        .ok_or(AttributesError::MissingThreshold)?;
    if attr.len() != 1 {
        return Err(AttributesError::InvalidAttributeValue(attr.len() as u8).into());
    }
    Ok(attr[0])
}

fn check_depth_attribute(mk: &Multikey, wire_depth: u8) -> Result<(), Error> {
    let expected = depth_attr_value(mk)?;
    if expected != wire_depth {
        return Err(AttributesError::DepthMismatch {
            expected,
            found: wire_depth,
        }
        .into());
    }
    Ok(())
}

/// Extract and validate the depth byte embedded at `offset` of the wire data.
fn wire_depth_at(bytes: &[u8], offset: usize) -> Result<u8, Error> {
    bytes
        .get(offset)
        .copied()
        .ok_or(AttributesError::MissingKey.into())
}

/// Stamp the depth attribute on a Multikey builder (kept for symmetry with
/// the multisig depth helpers).
#[allow(dead_code)]
fn with_depth(builder: Builder, depth: u8) -> Builder {
    builder.with_depth(depth)
}

/// Parse the depth byte from merkle key-state bytes: `[version, depth, next_index, …]`.
fn state_depth(state: &[u8]) -> Result<u8, Error> {
    if state.len() < 3 || state[0] != MT_STATE_FORMAT_VERSION {
        return Err(
            AttributesError::InvalidAttributeValue(state.first().copied().unwrap_or(0)).into(),
        );
    }
    Ok(state[1])
}

fn public_from_private(codec: Codec, secret: &[u8]) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::LamportMerkleSha3256Priv => merkle_wrapper::public_from_private_256(secret),
        Codec::LamportMerkleSha3384Priv => merkle_wrapper::public_from_private_384(secret),
        Codec::LamportMerkleSha3512Priv => merkle_wrapper::public_from_private_512(secret),
        Codec::LamportMerkleSha2256Priv => merkle_wrapper::public_from_private_sha2_256(secret),
        Codec::LamportMerkleSha2384Priv => merkle_wrapper::public_from_private_sha2_384(secret),
        Codec::LamportMerkleSha2512Priv => merkle_wrapper::public_from_private_sha2_512(secret),
        Codec::LamportMerkleBlake2B512Priv => {
            merkle_wrapper::public_from_private_blake2b_512(secret)
        }
        Codec::LamportMerkleBlake2S256Priv => {
            merkle_wrapper::public_from_private_blake2s_256(secret)
        }
        Codec::LamportMerkleBlake3256Priv => merkle_wrapper::public_from_private_blake3_256(secret),
        Codec::LamportMerkleShake128Priv => merkle_wrapper::public_from_private_shake_128(secret),
        Codec::LamportMerkleShake256Priv => merkle_wrapper::public_from_private_shake_256(secret),
        _ => {
            return Err(ConversionsError::SecretKeyFailure(
                "not a merkle-Lamport private key".into(),
            )
            .into());
        }
    }
    .map_err(|e| ConversionsError::SecretKeyFailure(e).into())
}

fn keypair(codec: Codec, depth: u8) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    match codec {
        Codec::LamportMerkleSha3256Priv => merkle_wrapper::keypair_256(depth),
        Codec::LamportMerkleSha3384Priv => merkle_wrapper::keypair_384(depth),
        Codec::LamportMerkleSha3512Priv => merkle_wrapper::keypair_512(depth),
        Codec::LamportMerkleSha2256Priv => merkle_wrapper::keypair_sha2_256(depth),
        Codec::LamportMerkleSha2384Priv => merkle_wrapper::keypair_sha2_384(depth),
        Codec::LamportMerkleSha2512Priv => merkle_wrapper::keypair_sha2_512(depth),
        Codec::LamportMerkleBlake2B512Priv => merkle_wrapper::keypair_blake2b_512(depth),
        Codec::LamportMerkleBlake2S256Priv => merkle_wrapper::keypair_blake2s_256(depth),
        Codec::LamportMerkleBlake3256Priv => merkle_wrapper::keypair_blake3_256(depth),
        Codec::LamportMerkleShake128Priv => merkle_wrapper::keypair_shake_128(depth),
        Codec::LamportMerkleShake256Priv => merkle_wrapper::keypair_shake_256(depth),
        _ => {
            return Err(ConversionsError::SecretKeyFailure(
                "not a merkle-Lamport private key".into(),
            )
            .into());
        }
    }
    .map_err(|e| ConversionsError::SecretKeyFailure(e).into())
}

fn sign_bytes(
    codec: Codec,
    secret: &[u8],
    msg: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    match codec {
        Codec::LamportMerkleSha3256Priv => merkle_wrapper::sign_256(secret, msg),
        Codec::LamportMerkleSha3384Priv => merkle_wrapper::sign_384(secret, msg),
        Codec::LamportMerkleSha3512Priv => merkle_wrapper::sign_512(secret, msg),
        Codec::LamportMerkleSha2256Priv => merkle_wrapper::sign_sha2_256(secret, msg),
        Codec::LamportMerkleSha2384Priv => merkle_wrapper::sign_sha2_384(secret, msg),
        Codec::LamportMerkleSha2512Priv => merkle_wrapper::sign_sha2_512(secret, msg),
        Codec::LamportMerkleBlake2B512Priv => merkle_wrapper::sign_blake2b_512(secret, msg),
        Codec::LamportMerkleBlake2S256Priv => merkle_wrapper::sign_blake2s_256(secret, msg),
        Codec::LamportMerkleBlake3256Priv => merkle_wrapper::sign_blake3_256(secret, msg),
        Codec::LamportMerkleShake128Priv => merkle_wrapper::sign_shake_128(secret, msg),
        Codec::LamportMerkleShake256Priv => merkle_wrapper::sign_shake_256(secret, msg),
        _ => return Err(SignError::NotSigningKey.into()),
    }
    .map_err(|e| SignError::SigningFailed(e).into())
}

fn verify_bytes(codec: Codec, pub_bytes: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), Error> {
    match codec {
        Codec::LamportMerkleSha3256Pub => merkle_wrapper::verify_256(pub_bytes, sig, msg),
        Codec::LamportMerkleSha3384Pub => merkle_wrapper::verify_384(pub_bytes, sig, msg),
        Codec::LamportMerkleSha3512Pub => merkle_wrapper::verify_512(pub_bytes, sig, msg),
        Codec::LamportMerkleSha2256Pub => merkle_wrapper::verify_sha2_256(pub_bytes, sig, msg),
        Codec::LamportMerkleSha2384Pub => merkle_wrapper::verify_sha2_384(pub_bytes, sig, msg),
        Codec::LamportMerkleSha2512Pub => merkle_wrapper::verify_sha2_512(pub_bytes, sig, msg),
        Codec::LamportMerkleBlake2B512Pub => {
            merkle_wrapper::verify_blake2b_512(pub_bytes, sig, msg)
        }
        Codec::LamportMerkleBlake2S256Pub => {
            merkle_wrapper::verify_blake2s_256(pub_bytes, sig, msg)
        }
        Codec::LamportMerkleBlake3256Pub => merkle_wrapper::verify_blake3_256(pub_bytes, sig, msg),
        Codec::LamportMerkleShake128Pub => merkle_wrapper::verify_shake_128(pub_bytes, sig, msg),
        Codec::LamportMerkleShake256Pub => merkle_wrapper::verify_shake_256(pub_bytes, sig, msg),
        _ => {
            return Err(VerifyError::BadSignature("not a merkle-Lamport public key".into()).into());
        }
    }
    .map_err(|e| VerifyError::BadSignature(e).into())
}

fn split_bytes(
    codec: Codec,
    secret: &[u8],
    t: usize,
    n: usize,
) -> Result<Vec<Zeroizing<Vec<u8>>>, Error> {
    match codec {
        Codec::LamportMerkleSha3256Priv => merkle_wrapper::split_256(secret, t, n),
        Codec::LamportMerkleSha3384Priv => merkle_wrapper::split_384(secret, t, n),
        Codec::LamportMerkleSha3512Priv => merkle_wrapper::split_512(secret, t, n),
        Codec::LamportMerkleSha2256Priv => merkle_wrapper::split_sha2_256(secret, t, n),
        Codec::LamportMerkleSha2384Priv => merkle_wrapper::split_sha2_384(secret, t, n),
        Codec::LamportMerkleSha2512Priv => merkle_wrapper::split_sha2_512(secret, t, n),
        Codec::LamportMerkleBlake2B512Priv => merkle_wrapper::split_blake2b_512(secret, t, n),
        Codec::LamportMerkleBlake2S256Priv => merkle_wrapper::split_blake2s_256(secret, t, n),
        Codec::LamportMerkleBlake3256Priv => merkle_wrapper::split_blake3_256(secret, t, n),
        Codec::LamportMerkleShake128Priv => merkle_wrapper::split_shake_128(secret, t, n),
        Codec::LamportMerkleShake256Priv => merkle_wrapper::split_shake_256(secret, t, n),
        _ => return Err(ThresholdError::NotASecretKey.into()),
    }
    .map_err(|e| ThresholdError::ShareCombineFailed(e).into())
}

fn share_sign_bytes(codec: Codec, share: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::LamportMerkleSha3256PrivShare => merkle_wrapper::share_sign_256(share, msg),
        Codec::LamportMerkleSha3384PrivShare => merkle_wrapper::share_sign_384(share, msg),
        Codec::LamportMerkleSha3512PrivShare => merkle_wrapper::share_sign_512(share, msg),
        Codec::LamportMerkleSha2256PrivShare => merkle_wrapper::share_sign_sha2_256(share, msg),
        Codec::LamportMerkleSha2384PrivShare => merkle_wrapper::share_sign_sha2_384(share, msg),
        Codec::LamportMerkleSha2512PrivShare => merkle_wrapper::share_sign_sha2_512(share, msg),
        Codec::LamportMerkleBlake2B512PrivShare => {
            merkle_wrapper::share_sign_blake2b_512(share, msg)
        }
        Codec::LamportMerkleBlake2S256PrivShare => {
            merkle_wrapper::share_sign_blake2s_256(share, msg)
        }
        Codec::LamportMerkleBlake3256PrivShare => merkle_wrapper::share_sign_blake3_256(share, msg),
        Codec::LamportMerkleShake128PrivShare => merkle_wrapper::share_sign_shake_128(share, msg),
        Codec::LamportMerkleShake256PrivShare => merkle_wrapper::share_sign_shake_256(share, msg),
        _ => return Err(SignError::NotSigningKey.into()),
    }
    .map_err(|e| SignError::SigningFailed(e).into())
}

pub(crate) struct View<'a> {
    mk: &'a Multikey,
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk })
    }
}

impl<'a> AttrView for View<'a> {
    fn is_encrypted(&self) -> bool {
        false
    }
    fn is_secret_key(&self) -> bool {
        is_merkle_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_merkle_pub(self.mk.codec)
    }
    fn is_secret_key_share(&self) -> bool {
        is_merkle_priv_share(self.mk.codec)
    }
}

impl<'a> DataView for View<'a> {
    fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key = self
            .mk
            .attributes
            .get(&AttrId::KeyData)
            .ok_or(AttributesError::MissingKey)?;
        Ok(key.clone())
    }
    fn secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !self.is_secret_key() {
            return Err(AttributesError::NotSecretKey(self.mk.codec).into());
        }
        self.key_bytes()
    }
}

impl<'a> ConvView for View<'a> {
    fn to_public_key(&self) -> Result<Multikey, Error> {
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        let depth = wire_depth_at(secret_bytes.as_slice(), 1)?;
        check_depth_attribute(self.mk, depth)?;
        let pub_bytes = public_from_private(self.mk.codec, secret_bytes.as_slice())?;
        Builder::new(public_codec(self.mk.codec)?)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .with_depth(depth)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Merkle-Lamport not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Merkle-Lamport not supported in SSH key format".into(),
        )
        .into())
    }
}

impl<'a> FingerprintView for View<'a> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        let pub_bytes = if self.is_secret_key() {
            let pk = self.to_public_key()?;
            let dv = pk.data_view()?;
            dv.key_bytes()?
        } else {
            self.key_bytes()?
        };
        Ok(mh::Builder::new_from_bytes(codec, pub_bytes.as_slice())?.try_build()?)
    }
}

impl<'a> SignView for View<'a> {
    /// Not supported for merkle keys: signing consumes a one-time leaf and the
    /// caller must persist the advanced state. Use [`SignView::sign_advance`].
    fn sign(
        &self,
        _msg: &[u8],
        _combined: bool,
        _scheme: Option<u8>,
    ) -> Result<ms::Multisig, Error> {
        Err(Error::UnsupportedAlgorithm(
            "merkle-Lamport keys are stateful; use sign_advance to consume a leaf and persist \
             the advanced state"
                .into(),
        ))
    }

    /// Sign at the next leaf, returning the Multisig AND the advanced Multikey.
    /// The caller MUST persist the advanced key so the consumed leaf index is
    /// never reused.
    fn sign_advance(
        &self,
        msg: &[u8],
        combined: bool,
        _scheme: Option<u8>,
    ) -> Result<(ms::Multisig, Multikey), Error> {
        let codec = self.mk.codec;
        let key_bytes = {
            let kd = self.mk.data_view()?;
            kd.key_bytes()?
        };
        // A private-key SHARE signs to a signature SHARE (stateful, but the
        // share state is not persisted here — combine on the multisig instead);
        // a full private key signs with its next leaf and MUST be advanced.
        if is_merkle_priv_share(codec) {
            let sig = share_sign_bytes(codec, key_bytes.as_slice(), msg)?;
            let out_codec = share_sig_codec(codec)?;
            let mut msb = ms::Builder::new(out_codec).with_signature_bytes(&sig);
            if combined {
                msb = msb.with_message_bytes(&msg);
            }
            let depth = state_depth(key_bytes.as_slice())?;
            let mut sig_ms = msb.try_build()?;
            sig_ms.attributes.insert(MsAttrId::Depth, vec![depth]);
            return Ok((sig_ms, self.mk.clone()));
        }
        if !is_merkle_priv(codec) {
            return Err(SignError::NotSigningKey.into());
        }
        let depth = state_depth(key_bytes.as_slice())?;
        check_depth_attribute(self.mk, depth)?;
        let (sig, advanced) = sign_bytes(codec, key_bytes.as_slice(), msg)?;
        let out_codec = sig_codec(codec)?;
        let mut msb = ms::Builder::new(out_codec).with_signature_bytes(&sig);
        if combined {
            msb = msb.with_message_bytes(&msg);
        }
        let mut sig_ms = msb.try_build()?;
        sig_ms.attributes.insert(MsAttrId::Depth, vec![depth]);
        let advanced_mk = Builder::new(codec)
            .with_comment(&self.mk.comment)
            .with_key_bytes(advanced.as_slice())
            .with_depth(depth)
            .try_build()?;
        Ok((sig_ms, advanced_mk))
    }
}

impl<'a> VerifyView for View<'a> {
    fn verify(&self, multisig: &ms::Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let msg_bytes = if let Some(m) = msg {
            m
        } else if !multisig.message.is_empty() {
            multisig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        let attr = self.mk.attr_view()?;
        let pubmk = if attr.is_secret_key() {
            self.mk.conv_view()?.to_public_key()?
        } else {
            self.mk.clone()
        };
        let key_bytes = {
            let kd = pubmk.data_view()?;
            kd.key_bytes()?
        };
        // Cross-check the pubkey's depth attribute against the MtVerifyingKey
        // wire depth (byte 0) and the signature wire depth (byte 0).
        let key_depth = wire_depth_at(key_bytes.as_slice(), 0)?;
        check_depth_attribute(&pubmk, key_depth)?;
        let sv = multisig.data_view()?;
        let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;
        let sig_depth = wire_depth_at(&sig, 0)?;
        if sig_depth != key_depth {
            return Err(AttributesError::DepthMismatch {
                expected: key_depth,
                found: sig_depth,
            }
            .into());
        }
        if let Ok(ms_depth) = multisig_depth(multisig)
            && ms_depth != sig_depth
        {
            return Err(AttributesError::DepthMismatch {
                expected: ms_depth,
                found: sig_depth,
            }
            .into());
        }
        verify_bytes(pubmk.codec, key_bytes.as_slice(), &sig, msg_bytes)
    }
}

impl<'a> ThresholdView for View<'a> {
    /// Split a merkle-Lamport signing key into `threshold`-of-`limit` key
    /// shares. Each returned Multikey is a `LamportMerkle*PrivShare` whose key
    /// data is a GF(256) share of the whole tree state that can sign
    /// independently to a signature share.
    fn split(&self, threshold: usize, limit: usize) -> Result<Vec<Multikey>, Error> {
        if !self.mk.attr_view()?.is_secret_key() {
            return Err(ThresholdError::NotASecretKey.into());
        }
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        let depth = state_depth(secret_bytes.as_slice())?;
        check_depth_attribute(self.mk, depth)?;
        let share_codec = priv_share_codec(self.mk.codec)?;
        let shares = split_bytes(self.mk.codec, secret_bytes.as_slice(), threshold, limit)?;
        shares
            .into_iter()
            .map(|share| {
                Builder::new(share_codec)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&share)
                    .with_depth(depth)
                    .try_build()
            })
            .collect()
    }

    /// Not supported: merkle-Lamport threshold signing never reconstructs the
    /// signing key. Combine signature shares on the multisig instead.
    fn add_share(&self, _share: &Multikey) -> Result<Multikey, Error> {
        Err(ThresholdError::ShareCombineFailed(
            "merkle-Lamport threshold signing does not reconstruct the signing key; combine \
             signature shares instead"
                .into(),
        )
        .into())
    }

    /// Not supported: see [`add_share`](Self::add_share).
    fn combine(&self) -> Result<Multikey, Error> {
        Err(ThresholdError::ShareCombineFailed(
            "merkle-Lamport threshold signing does not reconstruct the signing key; combine \
             signature shares instead"
                .into(),
        )
        .into())
    }

    /// Merkle-Lamport does not use encrypted threshold params; delegate to
    /// [`split`](Self::split).
    fn split_with_disclosure(
        &self,
        threshold: usize,
        limit: usize,
        _mode: crate::views::ThresholdDisclosure,
        _meta_key: Option<&Multikey>,
    ) -> Result<Vec<Multikey>, Error> {
        self.split(threshold, limit)
    }

    /// Merkle-Lamport does not use encrypted threshold params; delegate to
    /// [`add_share`](Self::add_share).
    fn add_share_with_meta(
        &self,
        share: &Multikey,
        _meta_key: Option<&Multikey>,
    ) -> Result<Multikey, Error> {
        self.add_share(share)
    }

    /// Merkle-Lamport does not use encrypted threshold params; delegate to
    /// [`combine`](Self::combine).
    fn combine_with_meta(&self, _meta_key: Option<&Multikey>) -> Result<Multikey, Error> {
        self.combine()
    }
}

impl<'a> MerkleStateView for View<'a> {
    fn depth(&self) -> Result<u8, Error> {
        let key_bytes = {
            let kd = self.mk.data_view()?;
            kd.key_bytes()?
        };
        let depth = if self.is_secret_key() {
            state_depth(key_bytes.as_slice())?
        } else {
            // MtVerifyingKey wire: [depth, root]
            wire_depth_at(key_bytes.as_slice(), 0)?
        };
        check_depth_attribute(self.mk, depth)?;
        Ok(depth)
    }

    fn capacity(&self) -> Result<usize, Error> {
        Ok(1usize << self.depth()?)
    }

    fn next_index(&self) -> Result<usize, Error> {
        if !self.is_secret_key() {
            return Err(AttributesError::NotSecretKey(self.mk.codec).into());
        }
        let key_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        // [version, depth, next_index, …]
        Ok(usize::from(wire_depth_at(key_bytes.as_slice(), 2)?))
    }

    fn remaining_signatures(&self) -> Result<usize, Error> {
        if !self.is_secret_key() {
            return Err(AttributesError::NotSecretKey(self.mk.codec).into());
        }
        let key_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        let sk = MtSigningKey::<Sha3_256Digest>::from_bytes(key_bytes.as_slice());
        // The digest type does not affect remaining count; parse generically
        // per codec instead.
        let _ = sk;
        remaining_from_state(key_bytes.as_slice(), self.mk.codec)
    }
}

/// Compute remaining signatures from state bytes without decoding secret
/// material: remaining = capacity - consumed, where the state carries exactly
/// `remaining` leaf key blocks after the leaf-hash section.
fn remaining_from_state(state: &[u8], codec: Codec) -> Result<usize, Error> {
    // state = [version, depth, next_index] || 2^depth leaf hashes || remaining secret blocks
    if state.len() < 3 {
        return Err(AttributesError::MissingKey.into());
    }
    let depth = state[1];
    if !(1..=3).contains(&depth) {
        return Err(AttributesError::InvalidAttributeValue(depth).into());
    }
    let capacity = 1usize << depth;
    let hash_size = digest_bytes_for(codec)?;
    let leaves_len = capacity
        .checked_mul(hash_size)
        .ok_or(Error::InputTooLarge {
            claimed: capacity,
            max: MAX_DECODED_SIZE,
        })?;
    let header = 3 + leaves_len;
    if state.len() < header {
        return Err(AttributesError::MissingKey.into());
    }
    let material_size = signing_key_material_size_for(codec)?;
    let rest = state.len() - header;
    if !rest.is_multiple_of(material_size) {
        return Err(AttributesError::InvalidAttributeValue(depth).into());
    }
    let next_index = usize::from(state[2]);
    if next_index + rest / material_size != capacity {
        return Err(AttributesError::InvalidAttributeValue(depth).into());
    }
    Ok(rest / material_size)
}

/// Digest size in bytes for a merkle-Lamport codec.
fn digest_bytes_for(codec: Codec) -> Result<usize, Error> {
    const D: usize = 32;
    const D48: usize = 48;
    const D64: usize = 64;
    Ok(match codec {
        Codec::LamportMerkleSha3256Pub
        | Codec::LamportMerkleSha3256Priv
        | Codec::LamportMerkleSha3256PrivShare
        | Codec::LamportMerkleSha3256Sig
        | Codec::LamportMerkleSha3256SigShare
        | Codec::LamportMerkleSha2256Pub
        | Codec::LamportMerkleSha2256Priv
        | Codec::LamportMerkleSha2256PrivShare
        | Codec::LamportMerkleSha2256Sig
        | Codec::LamportMerkleSha2256SigShare
        | Codec::LamportMerkleBlake2S256Pub
        | Codec::LamportMerkleBlake2S256Priv
        | Codec::LamportMerkleBlake2S256PrivShare
        | Codec::LamportMerkleBlake2S256Sig
        | Codec::LamportMerkleBlake2S256SigShare
        | Codec::LamportMerkleBlake3256Pub
        | Codec::LamportMerkleBlake3256Priv
        | Codec::LamportMerkleBlake3256PrivShare
        | Codec::LamportMerkleBlake3256Sig
        | Codec::LamportMerkleBlake3256SigShare => D,
        Codec::LamportMerkleSha3384Pub
        | Codec::LamportMerkleSha3384Priv
        | Codec::LamportMerkleSha3384PrivShare
        | Codec::LamportMerkleSha3384Sig
        | Codec::LamportMerkleSha3384SigShare
        | Codec::LamportMerkleSha2384Pub
        | Codec::LamportMerkleSha2384Priv
        | Codec::LamportMerkleSha2384PrivShare
        | Codec::LamportMerkleSha2384Sig
        | Codec::LamportMerkleSha2384SigShare => D48,
        Codec::LamportMerkleSha3512Pub
        | Codec::LamportMerkleSha3512Priv
        | Codec::LamportMerkleSha3512PrivShare
        | Codec::LamportMerkleSha3512Sig
        | Codec::LamportMerkleSha3512SigShare
        | Codec::LamportMerkleSha2512Pub
        | Codec::LamportMerkleSha2512Priv
        | Codec::LamportMerkleSha2512PrivShare
        | Codec::LamportMerkleSha2512Sig
        | Codec::LamportMerkleSha2512SigShare
        | Codec::LamportMerkleBlake2B512Pub
        | Codec::LamportMerkleBlake2B512Priv
        | Codec::LamportMerkleBlake2B512PrivShare
        | Codec::LamportMerkleBlake2B512Sig
        | Codec::LamportMerkleBlake2B512SigShare
        | Codec::LamportMerkleShake128Pub
        | Codec::LamportMerkleShake128Priv
        | Codec::LamportMerkleShake128PrivShare
        | Codec::LamportMerkleShake128Sig
        | Codec::LamportMerkleShake128SigShare
        | Codec::LamportMerkleShake256Pub
        | Codec::LamportMerkleShake256Priv
        | Codec::LamportMerkleShake256PrivShare
        | Codec::LamportMerkleShake256Sig
        | Codec::LamportMerkleShake256SigShare => D64,
        _ => return Err(AttributesError::UnsupportedCodec(codec).into()),
    })
}

/// Lamport signing key secret-material size (bits × bytes × 2) for a codec.
fn signing_key_material_size_for(codec: Codec) -> Result<usize, Error> {
    let digest = digest_bytes_for(codec)?;
    let bits = digest * 8;
    Ok(2 * bits * digest)
}

/// Generate a depth-1 merkle-Lamport private key (unused since 1.2.2: the
/// plain `Builder::new_from_random_bytes` path stamps depth inline; kept for
/// symmetry with the other view helpers).
#[allow(dead_code)]
pub(crate) fn generate_private_key(codec: Codec) -> Result<Zeroizing<Vec<u8>>, Error> {
    generate_private_key_with_depth(codec, 1)
}

/// Generate a merkle-Lamport private key of the given depth (1..=3).
pub(crate) fn generate_private_key_with_depth(
    codec: Codec,
    depth: u8,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !(1..=3).contains(&depth) {
        return Err(ThresholdError::InvalidThresholdLimit(depth as usize, 3).into());
    }
    let (_pk, sk) = keypair(codec, depth)?;
    Ok(sk)
}

const MAX_DECODED_SIZE: usize = crate::mk::MAX_DECODED_SIZE;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LAMPORT_MERKLE_KEY_CODECS;
    use multi_sig::AttrId as MsAttrId;

    fn build_priv(codec: Codec, depth: u8) -> Multikey {
        Builder::new_from_random_bytes_with_depth(codec, depth, &mut rand::rng())
            .unwrap()
            .try_build()
            .unwrap()
    }

    fn merkle_priv_codecs() -> impl Iterator<Item = Codec> {
        LAMPORT_MERKLE_KEY_CODECS.into_iter().filter(|c| {
            matches!(
                c,
                Codec::LamportMerkleSha3512Priv
                    | Codec::LamportMerkleSha3384Priv
                    | Codec::LamportMerkleSha3256Priv
                    | Codec::LamportMerkleSha2512Priv
                    | Codec::LamportMerkleSha2384Priv
                    | Codec::LamportMerkleSha2256Priv
                    | Codec::LamportMerkleBlake2B512Priv
                    | Codec::LamportMerkleBlake2S256Priv
                    | Codec::LamportMerkleBlake3256Priv
                    | Codec::LamportMerkleShake128Priv
                    | Codec::LamportMerkleShake256Priv
            )
        })
    }

    #[test]
    fn test_merkle_roundtrip_all_digests_depth1() {
        for codec in merkle_priv_codecs() {
            let sk = build_priv(codec, 1);
            let pk = sk.conv_view().unwrap().to_public_key().unwrap();

            // depth attribute stamped and cross-checked
            assert_eq!(pk.attributes.get(&AttrId::Depth).map(|b| b[0]), Some(1));

            let msg = b"merkle roundtrip";
            let (ms, advanced) = sk
                .sign_view()
                .unwrap()
                .sign_advance(msg, false, None)
                .unwrap();
            assert_eq!(ms.attributes.get(&MsAttrId::Depth).map(|b| b[0]), Some(1));

            pk.verify_view().unwrap().verify(&ms, Some(msg)).unwrap();
            sk.verify_view().unwrap().verify(&ms, Some(msg)).unwrap();

            // tampered message must fail
            assert!(
                pk.verify_view()
                    .unwrap()
                    .verify(&ms, Some(b"tampered"))
                    .is_err()
            );

            // advanced key has one fewer remaining signature
            let sv = sk.merkle_state_view().unwrap();
            let av = advanced.merkle_state_view().unwrap();
            assert_eq!(av.next_index().unwrap(), sv.next_index().unwrap() + 1);
        }
    }

    #[test]
    fn test_merkle_sign_rejected_sign_advance_required() {
        let sk = build_priv(Codec::LamportMerkleSha3256Priv, 1);
        assert!(sk.sign_view().unwrap().sign(b"x", false, None).is_err());
    }

    #[test]
    fn test_merkle_depth_validation() {
        // depth 0 and 4 must fail
        assert!(
            Builder::new_from_random_bytes_with_depth(
                Codec::LamportMerkleSha3256Priv,
                0,
                &mut rand::rng()
            )
            .is_err()
        );
        assert!(
            Builder::new_from_random_bytes_with_depth(
                Codec::LamportMerkleSha3256Priv,
                4,
                &mut rand::rng()
            )
            .is_err()
        );
    }

    #[test]
    fn test_merkle_plain_ctor_stamps_depth() {
        // The plain constructor generates a depth-1 tree and must stamp the
        // mandatory depth attribute (fixed in 1.2.2).
        let sk =
            Builder::new_from_random_bytes(Codec::LamportMerkleBlake3256Priv, &mut rand::rng())
                .unwrap()
                .try_build()
                .unwrap();
        assert_eq!(sk.attributes.get(&AttrId::Depth).map(|b| b[0]), Some(1));

        // the key must be fully usable: public derivation and signing
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        let msg = b"plain ctor roundtrip";
        let (ms, advanced) = sk
            .sign_view()
            .unwrap()
            .sign_advance(msg, false, None)
            .unwrap();
        pk.verify_view().unwrap().verify(&ms, Some(msg)).unwrap();
        let av = advanced.merkle_state_view().unwrap();
        assert_eq!(av.next_index().unwrap(), 1);
        assert_eq!(av.remaining_signatures().unwrap(), 1);
    }

    #[test]
    fn test_merkle_depth3_sha3_256() {
        let sk = build_priv(Codec::LamportMerkleSha3256Priv, 3);
        let sv = sk.merkle_state_view().unwrap();
        assert_eq!(sv.depth().unwrap(), 3);
        assert_eq!(sv.capacity().unwrap(), 8);
        assert_eq!(sv.next_index().unwrap(), 0);
        assert_eq!(sv.remaining_signatures().unwrap(), 8);

        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        let msg = b"depth three";
        let (ms, mut advanced) = sk
            .sign_view()
            .unwrap()
            .sign_advance(msg, true, None)
            .unwrap();
        assert_eq!(ms.message, msg.to_vec());
        pk.verify_view().unwrap().verify(&ms, Some(msg)).unwrap();
        // exhaust the tree
        for i in 1..8 {
            let m = format!("m{i}");
            let (m2, adv2) = advanced
                .sign_view()
                .unwrap()
                .sign_advance(m.as_bytes(), false, None)
                .unwrap();
            pk.verify_view()
                .unwrap()
                .verify(&m2, Some(m.as_bytes()))
                .unwrap();
            advanced = adv2;
        }
        let av = advanced.merkle_state_view().unwrap();
        assert_eq!(av.remaining_signatures().unwrap(), 0);
        assert!(
            advanced
                .sign_view()
                .unwrap()
                .sign_advance(b"m9", false, None)
                .is_err()
        );
    }

    #[test]
    fn test_merkle_depth_mismatch_rejected() {
        let sk = build_priv(Codec::LamportMerkleSha3256Priv, 2);
        // tamper the depth attribute: wire says 2, attr now says 3
        let mut tampered = sk.clone();
        tampered
            .attributes
            .insert(AttrId::Depth, Zeroizing::new(vec![3]));
        assert!(tampered.conv_view().unwrap().to_public_key().is_err());
        assert!(tampered.merkle_state_view().unwrap().depth().is_err());
        // sign_advance cross-checks too
        assert!(
            tampered
                .sign_view()
                .unwrap()
                .sign_advance(b"m", false, None)
                .is_err()
        );
    }

    #[test]
    fn test_merkle_threshold_flow() {
        let sk = build_priv(Codec::LamportMerkleSha3256Priv, 1);
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        let msg = b"threshold merkle";

        // split 2-of-3
        let shares = sk.threshold_view().unwrap().split(2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        for share in &shares {
            assert!(share.attr_view().unwrap().is_secret_key_share());
            assert_eq!(share.attributes.get(&AttrId::Depth).map(|b| b[0]), Some(1));
        }

        // two participants sign to signature shares
        let s1 = shares[0]
            .sign_view()
            .unwrap()
            .sign_advance(msg, false, None)
            .unwrap()
            .0;
        let s2 = shares[1]
            .sign_view()
            .unwrap()
            .sign_advance(msg, false, None)
            .unwrap()
            .0;

        // accumulate on the multisig and combine
        let mut acc = ms::Builder::new(Codec::LamportMerkleSha3256Sig)
            .with_message_bytes(&msg)
            .try_build()
            .unwrap();
        for share_ms in [&s1, &s2] {
            let next = acc.threshold_view().unwrap().add_share(share_ms).unwrap();
            acc = next;
        }
        let combined = acc.threshold_view().unwrap().combine().unwrap();
        pk.verify_view()
            .unwrap()
            .verify(&combined, Some(msg))
            .unwrap();
    }

    #[test]
    fn test_merkle_introspection_depth1() {
        let sk = build_priv(Codec::LamportMerkleSha2256Priv, 1);
        let sv = sk.merkle_state_view().unwrap();
        assert_eq!(sv.depth().unwrap(), 1);
        assert_eq!(sv.capacity().unwrap(), 2);
        assert_eq!(sv.next_index().unwrap(), 0);
        assert_eq!(sv.remaining_signatures().unwrap(), 2);

        // public keys expose depth/capacity only
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        let pv = pk.merkle_state_view().unwrap();
        assert_eq!(pv.depth().unwrap(), 1);
        assert_eq!(pv.capacity().unwrap(), 2);
        assert!(pv.next_index().is_err());
        assert!(pv.remaining_signatures().is_err());
    }

    #[test]
    fn test_merkle_sig_index_absent() {
        let sk = build_priv(Codec::LamportMerkleBlake3256Priv, 1);
        let (ms, _adv) = sk
            .sign_view()
            .unwrap()
            .sign_advance(b"m", false, None)
            .unwrap();
        // leaf index travels inside the Mt wire format, not as SigIndex
        assert!(ms.sig_index().is_none());
        let _ = MsAttrId::SigData;
    }
}
