// SPDX-License-Identifier: Apache-2.0
//! Shared BLS12-381 G1 helpers for Birds-of-Prey-1 hybrid signatures.
//!
//! BLS-G1 (blsful `Bls12381G1Impl`, "minimal-signature-size"): secret = 32 bytes,
//! public key = 96 bytes (G2 point), signature = 48 bytes (G1 point). The hybrid
//! schemes use a fixed `Basic` signature scheme.

use crate::Error;
use crate::error::{ConversionsError, SignError, VerifyError};
use blsful::inner_types::{G1Projective, GroupEncoding};
use blsful::{Bls12381G1Impl, PublicKey, SecretKey, Signature, SignatureSchemes};

pub(crate) const BLS_G1_SECRET_LEN: usize = 32;
pub(crate) const BLS_G1_PUB_LEN: usize = 96;
pub(crate) const BLS_G1_SIG_LEN: usize = 48;

fn secret_from_bytes(secret: &[u8]) -> Result<SecretKey<Bls12381G1Impl>, Error> {
    let arr: [u8; BLS_G1_SECRET_LEN] = secret
        .get(..BLS_G1_SECRET_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConversionsError::SecretKeyFailure("invalid BLS-G1 secret".to_string()))?;
    Option::from(SecretKey::from_be_bytes(&arr)).ok_or_else(|| {
        ConversionsError::SecretKeyFailure("invalid BLS-G1 secret".to_string()).into()
    })
}

/// Derive the 96-byte BLS-G1 public key (G2 point) from the secret.
pub(crate) fn public_from_secret(secret: &[u8]) -> Result<Vec<u8>, Error> {
    let sk = secret_from_bytes(secret)?;
    Ok(sk.public_key().0.to_bytes().as_ref().to_vec())
}

/// Sign `msg` with the BLS-G1 secret, returning the 48-byte signature.
pub(crate) fn sign(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let sk = secret_from_bytes(secret)?;
    let sig = sk
        .sign(SignatureSchemes::Basic, msg)
        .map_err(|e| SignError::SigningFailed(e.to_string()))?;
    Ok(sig.as_raw_value().to_bytes().as_ref().to_vec())
}

/// Verify a 48-byte BLS-G1 signature against the 96-byte public key.
pub(crate) fn verify(public: &[u8], sig_bytes: &[u8], msg: &[u8]) -> Result<(), Error> {
    let pk = PublicKey::<Bls12381G1Impl>::try_from(&public.to_vec())
        .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
    let arr: [u8; BLS_G1_SIG_LEN] = sig_bytes
        .try_into()
        .map_err(|_| VerifyError::BadSignature("invalid BLS-G1 signature length".to_string()))?;
    let group = Option::from(G1Projective::from_compressed(&arr))
        .ok_or_else(|| VerifyError::BadSignature("invalid BLS-G1 signature point".to_string()))?;
    let sig = Signature::<Bls12381G1Impl>::Basic(group);
    sig.verify(&pk, msg)
        .map_err(|e| VerifyError::BadSignature(format!("BLS-G1 verify failed: {}", e)).into())
}
