// SPDX-License-Identifier: Apache-2.0
//! Lamport one-time hash-based signature multikey view
//! (SHA3/SHA2/BLAKE2/BLAKE3 digest families).
//!
//! ⚠️ Lamport keys are ONE-TIME: signing two messages with the same key leaks
//! the secret key. This view signs at the byte level and does not itself enforce
//! single use; the provenance-log / keystore layer must reject a second
//! signature by the same Lamport public key.

use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    ThresholdView, VerifyView,
    error::{AttributesError, ConversionsError, SignError, ThresholdError, VerifyError},
    views::Views,
};
use blake2::{Blake2b512, Blake2s256};
use lamport_signature_plus::{
    LamportDigest, LamportExtendableDigest, LamportFixedDigest, Signature, SigningKey,
    SigningKeyShare, VerifyingKey, generate_keys,
};
use multi_codec::Codec;
use multi_hash::{Multihash, mh};
use multi_sig::{Views as _, ms};
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};
use shake::{Shake128, Shake256};
use zeroize::Zeroizing;

// ---- Inlined bs-lamport wrapper logic ----
// These generic functions replicate the bs-lamport crate's macro-generated
// wrappers, calling lamport_signature_plus directly.

type Sha3_256Digest = LamportFixedDigest<Sha3_256>;
type Sha3_384Digest = LamportFixedDigest<Sha3_384>;
type Sha3_512Digest = LamportFixedDigest<Sha3_512>;
type Sha2_256Digest = LamportFixedDigest<Sha256>;
type Sha2_384Digest = LamportFixedDigest<Sha384>;
type Sha2_512Digest = LamportFixedDigest<Sha512>;
type Blake2b512Digest = LamportFixedDigest<Blake2b512>;
type Blake2s256Digest = LamportFixedDigest<Blake2s256>;
type Shake128Digest = LamportExtendableDigest<Shake128>;
type Shake256Digest = LamportExtendableDigest<Shake256>;

#[derive(Copy, Clone, Debug, Default)]
pub struct Blake3_256Digest;

impl LamportDigest for Blake3_256Digest {
    fn digest_size_in_bits() -> usize {
        256
    }
    fn digest(data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }
}

mod lamport_wrapper {
    use super::{
        Blake2b512Digest, Blake2s256Digest, Blake3_256Digest, LamportDigest, Sha2_256Digest,
        Sha2_384Digest, Sha2_512Digest, Sha3_256Digest, Sha3_384Digest, Sha3_512Digest,
        Shake128Digest, Shake256Digest, Signature, SigningKey, SigningKeyShare, VerifyingKey,
        Zeroizing, generate_keys,
    };

    pub fn keypair<T: LamportDigest>() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        let (sk, pk) = generate_keys::<T, _>(rand::rng());
        (pk.to_bytes(), Zeroizing::new(sk.to_bytes()))
    }

    pub fn public_from_private<T: LamportDigest>(
        secret_key_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let sk = SigningKey::<T>::from_bytes(secret_key_bytes).map_err(|e| e.to_string())?;
        Ok(VerifyingKey::from(&sk).to_bytes())
    }

    pub fn sign<T: LamportDigest>(secret_key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        let mut sk = SigningKey::<T>::from_bytes(secret_key_bytes).map_err(|e| e.to_string())?;
        Ok(sk.sign(msg).map_err(|e| e.to_string())?.to_bytes())
    }

    pub fn verify<T: LamportDigest>(
        public_key_bytes: &[u8],
        signature_bytes: &[u8],
        msg: &[u8],
    ) -> Result<(), String> {
        let pk = VerifyingKey::<T>::from_bytes(public_key_bytes).map_err(|e| e.to_string())?;
        let sig = Signature::<T>::from_bytes(signature_bytes).map_err(|e| e.to_string())?;
        pk.verify(&sig, msg).map_err(|e| e.to_string())
    }

    pub fn split<T: LamportDigest>(
        secret_key_bytes: &[u8],
        threshold: usize,
        limit: usize,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, String> {
        let sk = SigningKey::<T>::from_bytes(secret_key_bytes).map_err(|e| e.to_string())?;
        let shares = sk
            .split(threshold, limit, rand::rng())
            .map_err(|e| e.to_string())?;
        Ok(shares
            .iter()
            .map(|s| Zeroizing::new(s.to_bytes()))
            .collect())
    }

    pub fn share_sign<T: LamportDigest>(share_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        let mut share = SigningKeyShare::<T>::from_bytes(share_bytes).map_err(|e| e.to_string())?;
        Ok(share.sign(msg).map_err(|e| e.to_string())?.to_bytes())
    }

    macro_rules! variant {
        ($digest:ty, $kp:ident, $pfp:ident, $sign:ident, $verify:ident, $split:ident, $share_sign:ident) => {
            pub fn $kp() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
                keypair::<$digest>()
            }
            pub fn $pfp(s: &[u8]) -> Result<Vec<u8>, String> {
                public_from_private::<$digest>(s)
            }
            pub fn $sign(s: &[u8], m: &[u8]) -> Result<Vec<u8>, String> {
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

fn is_lamport_priv(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::LamportSha3256Priv
            | Codec::LamportSha3384Priv
            | Codec::LamportSha3512Priv
            | Codec::LamportSha2256Priv
            | Codec::LamportSha2384Priv
            | Codec::LamportSha2512Priv
            | Codec::LamportBlake2B512Priv
            | Codec::LamportBlake2S256Priv
            | Codec::LamportBlake3256Priv
            | Codec::LamportShake128Priv
            | Codec::LamportShake256Priv
    )
}

fn is_lamport_pub(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::LamportSha3256Pub
            | Codec::LamportSha3384Pub
            | Codec::LamportSha3512Pub
            | Codec::LamportSha2256Pub
            | Codec::LamportSha2384Pub
            | Codec::LamportSha2512Pub
            | Codec::LamportBlake2B512Pub
            | Codec::LamportBlake2S256Pub
            | Codec::LamportBlake3256Pub
            | Codec::LamportShake128Pub
            | Codec::LamportShake256Pub
    )
}

fn public_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportSha3256Priv => Ok(Codec::LamportSha3256Pub),
        Codec::LamportSha3384Priv => Ok(Codec::LamportSha3384Pub),
        Codec::LamportSha3512Priv => Ok(Codec::LamportSha3512Pub),
        Codec::LamportSha2256Priv => Ok(Codec::LamportSha2256Pub),
        Codec::LamportSha2384Priv => Ok(Codec::LamportSha2384Pub),
        Codec::LamportSha2512Priv => Ok(Codec::LamportSha2512Pub),
        Codec::LamportBlake2B512Priv => Ok(Codec::LamportBlake2B512Pub),
        Codec::LamportBlake2S256Priv => Ok(Codec::LamportBlake2S256Pub),
        Codec::LamportBlake3256Priv => Ok(Codec::LamportBlake3256Pub),
        Codec::LamportShake128Priv => Ok(Codec::LamportShake128Pub),
        Codec::LamportShake256Priv => Ok(Codec::LamportShake256Pub),
        _ => Err(ConversionsError::SecretKeyFailure("not a Lamport private key".into()).into()),
    }
}

fn sig_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportSha3256Priv => Ok(Codec::LamportSha3256Sig),
        Codec::LamportSha3384Priv => Ok(Codec::LamportSha3384Sig),
        Codec::LamportSha3512Priv => Ok(Codec::LamportSha3512Sig),
        Codec::LamportSha2256Priv => Ok(Codec::LamportSha2256Sig),
        Codec::LamportSha2384Priv => Ok(Codec::LamportSha2384Sig),
        Codec::LamportSha2512Priv => Ok(Codec::LamportSha2512Sig),
        Codec::LamportBlake2B512Priv => Ok(Codec::LamportBlake2B512Sig),
        Codec::LamportBlake2S256Priv => Ok(Codec::LamportBlake2S256Sig),
        Codec::LamportBlake3256Priv => Ok(Codec::LamportBlake3256Sig),
        Codec::LamportShake128Priv => Ok(Codec::LamportShake128Sig),
        Codec::LamportShake256Priv => Ok(Codec::LamportShake256Sig),
        _ => Err(SignError::NotSigningKey.into()),
    }
}

fn public_from_private(codec: Codec, secret: &[u8]) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::LamportSha3256Priv => lamport_wrapper::public_from_private_256(secret),
        Codec::LamportSha3384Priv => lamport_wrapper::public_from_private_384(secret),
        Codec::LamportSha3512Priv => lamport_wrapper::public_from_private_512(secret),
        Codec::LamportSha2256Priv => lamport_wrapper::public_from_private_sha2_256(secret),
        Codec::LamportSha2384Priv => lamport_wrapper::public_from_private_sha2_384(secret),
        Codec::LamportSha2512Priv => lamport_wrapper::public_from_private_sha2_512(secret),
        Codec::LamportBlake2B512Priv => lamport_wrapper::public_from_private_blake2b_512(secret),
        Codec::LamportBlake2S256Priv => lamport_wrapper::public_from_private_blake2s_256(secret),
        Codec::LamportBlake3256Priv => lamport_wrapper::public_from_private_blake3_256(secret),
        Codec::LamportShake128Priv => lamport_wrapper::public_from_private_shake_128(secret),
        Codec::LamportShake256Priv => lamport_wrapper::public_from_private_shake_256(secret),
        _ => {
            return Err(
                ConversionsError::SecretKeyFailure("not a Lamport private key".into()).into(),
            );
        }
    }
    .map_err(|e| ConversionsError::SecretKeyFailure(e).into())
}

fn keypair(codec: Codec) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    match codec {
        Codec::LamportSha3256Priv => Ok(lamport_wrapper::keypair_256()),
        Codec::LamportSha3384Priv => Ok(lamport_wrapper::keypair_384()),
        Codec::LamportSha3512Priv => Ok(lamport_wrapper::keypair_512()),
        Codec::LamportSha2256Priv => Ok(lamport_wrapper::keypair_sha2_256()),
        Codec::LamportSha2384Priv => Ok(lamport_wrapper::keypair_sha2_384()),
        Codec::LamportSha2512Priv => Ok(lamport_wrapper::keypair_sha2_512()),
        Codec::LamportBlake2B512Priv => Ok(lamport_wrapper::keypair_blake2b_512()),
        Codec::LamportBlake2S256Priv => Ok(lamport_wrapper::keypair_blake2s_256()),
        Codec::LamportBlake3256Priv => Ok(lamport_wrapper::keypair_blake3_256()),
        Codec::LamportShake128Priv => Ok(lamport_wrapper::keypair_shake_128()),
        Codec::LamportShake256Priv => Ok(lamport_wrapper::keypair_shake_256()),
        _ => Err(ConversionsError::SecretKeyFailure("not a Lamport private key".into()).into()),
    }
}

fn sign_bytes(codec: Codec, secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::LamportSha3256Priv => lamport_wrapper::sign_256(secret, msg),
        Codec::LamportSha3384Priv => lamport_wrapper::sign_384(secret, msg),
        Codec::LamportSha3512Priv => lamport_wrapper::sign_512(secret, msg),
        Codec::LamportSha2256Priv => lamport_wrapper::sign_sha2_256(secret, msg),
        Codec::LamportSha2384Priv => lamport_wrapper::sign_sha2_384(secret, msg),
        Codec::LamportSha2512Priv => lamport_wrapper::sign_sha2_512(secret, msg),
        Codec::LamportBlake2B512Priv => lamport_wrapper::sign_blake2b_512(secret, msg),
        Codec::LamportBlake2S256Priv => lamport_wrapper::sign_blake2s_256(secret, msg),
        Codec::LamportBlake3256Priv => lamport_wrapper::sign_blake3_256(secret, msg),
        Codec::LamportShake128Priv => lamport_wrapper::sign_shake_128(secret, msg),
        Codec::LamportShake256Priv => lamport_wrapper::sign_shake_256(secret, msg),
        _ => return Err(SignError::NotSigningKey.into()),
    }
    .map_err(|e| SignError::SigningFailed(e).into())
}

fn verify_bytes(codec: Codec, pub_bytes: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), Error> {
    match codec {
        Codec::LamportSha3256Pub => lamport_wrapper::verify_256(pub_bytes, sig, msg),
        Codec::LamportSha3384Pub => lamport_wrapper::verify_384(pub_bytes, sig, msg),
        Codec::LamportSha3512Pub => lamport_wrapper::verify_512(pub_bytes, sig, msg),
        Codec::LamportSha2256Pub => lamport_wrapper::verify_sha2_256(pub_bytes, sig, msg),
        Codec::LamportSha2384Pub => lamport_wrapper::verify_sha2_384(pub_bytes, sig, msg),
        Codec::LamportSha2512Pub => lamport_wrapper::verify_sha2_512(pub_bytes, sig, msg),
        Codec::LamportBlake2B512Pub => lamport_wrapper::verify_blake2b_512(pub_bytes, sig, msg),
        Codec::LamportBlake2S256Pub => lamport_wrapper::verify_blake2s_256(pub_bytes, sig, msg),
        Codec::LamportBlake3256Pub => lamport_wrapper::verify_blake3_256(pub_bytes, sig, msg),
        Codec::LamportShake128Pub => lamport_wrapper::verify_shake_128(pub_bytes, sig, msg),
        Codec::LamportShake256Pub => lamport_wrapper::verify_shake_256(pub_bytes, sig, msg),
        _ => return Err(VerifyError::BadSignature("not a Lamport public key".into()).into()),
    }
    .map_err(|e| VerifyError::BadSignature(e).into())
}

fn is_lamport_priv_share(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::LamportSha3256PrivShare
            | Codec::LamportSha3384PrivShare
            | Codec::LamportSha3512PrivShare
            | Codec::LamportSha2256PrivShare
            | Codec::LamportSha2384PrivShare
            | Codec::LamportSha2512PrivShare
            | Codec::LamportBlake2B512PrivShare
            | Codec::LamportBlake2S256PrivShare
            | Codec::LamportBlake3256PrivShare
            | Codec::LamportShake128PrivShare
            | Codec::LamportShake256PrivShare
    )
}

/// Map a Lamport signing key/key-share codec to its signature-share codec.
fn share_sig_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportSha3256PrivShare => Ok(Codec::LamportSha3256SigShare),
        Codec::LamportSha3384PrivShare => Ok(Codec::LamportSha3384SigShare),
        Codec::LamportSha3512PrivShare => Ok(Codec::LamportSha3512SigShare),
        Codec::LamportSha2256PrivShare => Ok(Codec::LamportSha2256SigShare),
        Codec::LamportSha2384PrivShare => Ok(Codec::LamportSha2384SigShare),
        Codec::LamportSha2512PrivShare => Ok(Codec::LamportSha2512SigShare),
        Codec::LamportBlake2B512PrivShare => Ok(Codec::LamportBlake2B512SigShare),
        Codec::LamportBlake2S256PrivShare => Ok(Codec::LamportBlake2S256SigShare),
        Codec::LamportBlake3256PrivShare => Ok(Codec::LamportBlake3256SigShare),
        Codec::LamportShake128PrivShare => Ok(Codec::LamportShake128SigShare),
        Codec::LamportShake256PrivShare => Ok(Codec::LamportShake256SigShare),
        _ => Err(SignError::NotSigningKey.into()),
    }
}

/// Map a Lamport private key codec to its private-key-share codec.
fn priv_share_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::LamportSha3256Priv => Ok(Codec::LamportSha3256PrivShare),
        Codec::LamportSha3384Priv => Ok(Codec::LamportSha3384PrivShare),
        Codec::LamportSha3512Priv => Ok(Codec::LamportSha3512PrivShare),
        Codec::LamportSha2256Priv => Ok(Codec::LamportSha2256PrivShare),
        Codec::LamportSha2384Priv => Ok(Codec::LamportSha2384PrivShare),
        Codec::LamportSha2512Priv => Ok(Codec::LamportSha2512PrivShare),
        Codec::LamportBlake2B512Priv => Ok(Codec::LamportBlake2B512PrivShare),
        Codec::LamportBlake2S256Priv => Ok(Codec::LamportBlake2S256PrivShare),
        Codec::LamportBlake3256Priv => Ok(Codec::LamportBlake3256PrivShare),
        Codec::LamportShake128Priv => Ok(Codec::LamportShake128PrivShare),
        Codec::LamportShake256Priv => Ok(Codec::LamportShake256PrivShare),
        _ => Err(ThresholdError::NotASecretKey.into()),
    }
}

fn split_bytes(
    codec: Codec,
    secret: &[u8],
    t: usize,
    n: usize,
) -> Result<Vec<Zeroizing<Vec<u8>>>, Error> {
    match codec {
        Codec::LamportSha3256Priv => lamport_wrapper::split_256(secret, t, n),
        Codec::LamportSha3384Priv => lamport_wrapper::split_384(secret, t, n),
        Codec::LamportSha3512Priv => lamport_wrapper::split_512(secret, t, n),
        Codec::LamportSha2256Priv => lamport_wrapper::split_sha2_256(secret, t, n),
        Codec::LamportSha2384Priv => lamport_wrapper::split_sha2_384(secret, t, n),
        Codec::LamportSha2512Priv => lamport_wrapper::split_sha2_512(secret, t, n),
        Codec::LamportBlake2B512Priv => lamport_wrapper::split_blake2b_512(secret, t, n),
        Codec::LamportBlake2S256Priv => lamport_wrapper::split_blake2s_256(secret, t, n),
        Codec::LamportBlake3256Priv => lamport_wrapper::split_blake3_256(secret, t, n),
        Codec::LamportShake128Priv => lamport_wrapper::split_shake_128(secret, t, n),
        Codec::LamportShake256Priv => lamport_wrapper::split_shake_256(secret, t, n),
        _ => return Err(ThresholdError::NotASecretKey.into()),
    }
    .map_err(|e| ThresholdError::ShareCombineFailed(e).into())
}

fn share_sign_bytes(codec: Codec, share: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::LamportSha3256PrivShare => lamport_wrapper::share_sign_256(share, msg),
        Codec::LamportSha3384PrivShare => lamport_wrapper::share_sign_384(share, msg),
        Codec::LamportSha3512PrivShare => lamport_wrapper::share_sign_512(share, msg),
        Codec::LamportSha2256PrivShare => lamport_wrapper::share_sign_sha2_256(share, msg),
        Codec::LamportSha2384PrivShare => lamport_wrapper::share_sign_sha2_384(share, msg),
        Codec::LamportSha2512PrivShare => lamport_wrapper::share_sign_sha2_512(share, msg),
        Codec::LamportBlake2B512PrivShare => lamport_wrapper::share_sign_blake2b_512(share, msg),
        Codec::LamportBlake2S256PrivShare => lamport_wrapper::share_sign_blake2s_256(share, msg),
        Codec::LamportBlake3256PrivShare => lamport_wrapper::share_sign_blake3_256(share, msg),
        Codec::LamportShake128PrivShare => lamport_wrapper::share_sign_shake_128(share, msg),
        Codec::LamportShake256PrivShare => lamport_wrapper::share_sign_shake_256(share, msg),
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
        is_lamport_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_lamport_pub(self.mk.codec)
    }
    fn is_secret_key_share(&self) -> bool {
        is_lamport_priv_share(self.mk.codec)
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
        let pub_bytes = public_from_private(self.mk.codec, secret_bytes.as_slice())?;
        Builder::new(public_codec(self.mk.codec)?)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&pub_bytes)
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Lamport not supported in SSH key format".into(),
        )
        .into())
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(ConversionsError::UnsupportedAlgorithm(
            "Lamport not supported in SSH key format".into(),
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
    fn sign(&self, msg: &[u8], combined: bool, _scheme: Option<u8>) -> Result<ms::Multisig, Error> {
        let codec = self.mk.codec;
        let key_bytes = {
            let kd = self.mk.data_view()?;
            kd.key_bytes()?
        };
        // A private-key SHARE signs to a signature SHARE; a full private key
        // signs to a complete Lamport signature.
        let (sig, out_codec) = if is_lamport_priv_share(codec) {
            (
                share_sign_bytes(codec, key_bytes.as_slice(), msg)?,
                share_sig_codec(codec)?,
            )
        } else if is_lamport_priv(codec) {
            (
                sign_bytes(codec, key_bytes.as_slice(), msg)?,
                sig_codec(codec)?,
            )
        } else {
            return Err(SignError::NotSigningKey.into());
        };
        let mut msb = ms::Builder::new(out_codec).with_signature_bytes(&sig);
        if combined {
            msb = msb.with_message_bytes(&msg);
        }
        Ok(msb.try_build()?)
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
        let sv = multisig.data_view()?;
        let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;
        verify_bytes(pubmk.codec, key_bytes.as_slice(), &sig, msg_bytes)
    }
}

impl<'a> ThresholdView for View<'a> {
    /// Split a Lamport signing key into `threshold`-of-`limit` key shares. Each
    /// returned Multikey is a `Lamport*PrivShare` whose key data is a GF(256)
    /// Shamir share that can sign independently to a signature share.
    fn split(&self, threshold: usize, limit: usize) -> Result<Vec<Multikey>, Error> {
        if !self.mk.attr_view()?.is_secret_key() {
            return Err(ThresholdError::NotASecretKey.into());
        }
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        let share_codec = priv_share_codec(self.mk.codec)?;
        let shares = split_bytes(self.mk.codec, secret_bytes.as_slice(), threshold, limit)?;
        shares
            .into_iter()
            .map(|share| {
                Builder::new(share_codec)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&share)
                    .try_build()
            })
            .collect()
    }

    /// Not supported: Lamport threshold signing never reconstructs the signing
    /// key. Combine signature shares on the multisig instead.
    fn add_share(&self, _share: &Multikey) -> Result<Multikey, Error> {
        Err(ThresholdError::ShareCombineFailed(
            "Lamport threshold signing does not reconstruct the signing key; combine signature \
             shares instead"
                .into(),
        )
        .into())
    }

    /// Not supported: see [`add_share`](Self::add_share).
    fn combine(&self) -> Result<Multikey, Error> {
        Err(ThresholdError::ShareCombineFailed(
            "Lamport threshold signing does not reconstruct the signing key; combine signature \
             shares instead"
                .into(),
        )
        .into())
    }

    /// Lamport does not use encrypted threshold params; delegate to [`split`](Self::split).
    fn split_with_disclosure(
        &self,
        threshold: usize,
        limit: usize,
        _mode: crate::views::ThresholdDisclosure,
        _meta_key: Option<&Multikey>,
    ) -> Result<Vec<Multikey>, Error> {
        self.split(threshold, limit)
    }

    /// Lamport does not use encrypted threshold params; delegate to [`add_share`](Self::add_share).
    fn add_share_with_meta(
        &self,
        share: &Multikey,
        _meta_key: Option<&Multikey>,
    ) -> Result<Multikey, Error> {
        self.add_share(share)
    }

    /// Lamport does not use encrypted threshold params; delegate to [`combine`](Self::combine).
    fn combine_with_meta(&self, _meta_key: Option<&Multikey>) -> Result<Multikey, Error> {
        self.combine()
    }
}

pub(crate) fn generate_private_key(codec: Codec) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (_pk, sk) = keypair(codec)?;
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Builder as MkBuilder;

    #[test]
    fn test_lamport_sign_verify_roundtrip() {
        let mut rng = rand::rng();
        for codec in [
            Codec::LamportSha3256Priv,
            Codec::LamportSha3384Priv,
            Codec::LamportSha3512Priv,
            Codec::LamportSha2256Priv,
            Codec::LamportSha2384Priv,
            Codec::LamportSha2512Priv,
            Codec::LamportBlake2B512Priv,
            Codec::LamportBlake2S256Priv,
            Codec::LamportBlake3256Priv,
            Codec::LamportShake128Priv,
            Codec::LamportShake256Priv,
        ] {
            let sk = MkBuilder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .try_build()
                .unwrap();
            let pk = sk.conv_view().unwrap().to_public_key().unwrap();

            let msg = b"lamport multikey message";
            let ms = sk.sign_view().unwrap().sign(msg, false, None).unwrap();
            pk.verify_view().unwrap().verify(&ms, Some(msg)).unwrap();
            assert!(
                pk.verify_view()
                    .unwrap()
                    .verify(&ms, Some(b"tampered"))
                    .is_err()
            );
        }
    }

    #[test]
    fn test_lamport_threshold_sign_combine() {
        use multi_sig::Views as _;
        use multi_util::CodecInfo as _;

        let mut rng = rand::rng();
        let sk = MkBuilder::new_from_random_bytes(Codec::LamportSha3256Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        let msg = b"threshold lamport message";

        // split the signing key into 2-of-3 key shares
        let shares = sk.threshold_view().unwrap().split(2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert!(shares[0].attr_view().unwrap().is_secret_key_share());

        // any two shareholders each produce a signature share
        let share_sig_a = shares[0]
            .sign_view()
            .unwrap()
            .sign(msg, false, None)
            .unwrap();
        let share_sig_c = shares[2]
            .sign_view()
            .unwrap()
            .sign(msg, false, None)
            .unwrap();
        assert_eq!(share_sig_a.codec(), Codec::LamportSha3256SigShare);

        // accumulate the signature shares and combine into a full signature
        let acc = ms::Builder::new(Codec::LamportSha3256Sig)
            .try_build()
            .unwrap();
        let acc = acc
            .threshold_view()
            .unwrap()
            .add_share(&share_sig_a)
            .unwrap();
        let acc = acc
            .threshold_view()
            .unwrap()
            .add_share(&share_sig_c)
            .unwrap();
        let combined = acc.threshold_view().unwrap().combine().unwrap();
        assert_eq!(combined.codec(), Codec::LamportSha3256Sig);

        // the combined signature verifies under the ORIGINAL public key
        pk.verify_view()
            .unwrap()
            .verify(&combined, Some(msg))
            .unwrap();
    }
}
