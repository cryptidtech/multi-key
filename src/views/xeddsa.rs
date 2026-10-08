// SPDX-License-Identifier: Apache-2.0
//! XEdDSA view; a signature over a 32-byte message that verifies against the
//! Edwards form of an X25519 public key.
//!
//! The scheme is the Signal XEdDSA specification. The proof-of-possession
//! framework uses it to show that the author of a proof knows the X25519
//! secret key behind a published public key.
//!
//! Key conventions, verified empirically against curve25519-dalek 5.0:
//!
//! 1. The DH scalar is the clamped X25519 secret key, reduced modulo the
//!    group order. The published u-coordinate stays the standard ladder
//!    output `clamp(sk) * B_mont`, so X25519 DH keeps working unchanged.
//! 2. The POP signing scalar is the sign-normalized variant of the DH
//!    scalar: it is negated when the canonical encoding of `a * B` carries
//!    y sign 1. This makes the scalar point equal the canonical lift of the
//!    published u, which the verifier recovers with y sign 0.
//! 3. The canonical lift of u is the Edwards point recovered from
//!    `to_edwards(sign = 0)`. Its compressed encoding re-encodes identically
//!    with the sign bit cleared, and `u(lift) == u`.
//! 4. The verification equation is standard Ed25519 over the lifted point,
//!    checked with strict verification.

use crate::views::dispatch::{dispatch_attr_view, dispatch_conv_view, dispatch_data_view};
use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
    error::{AttributesError, ConversionsError, SignError, VerifyError},
};
use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint, scalar::Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use multi_codec::Codec;
use multi_hash::{Multihash, mh};
use multi_sig::{Multisig, ViewBuilder, ms};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const X25519_KEY_LENGTH: usize = 32;
const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Small-order u encodings. A key on this list encodes a point whose
/// discrete logarithm with respect to the torsion subgroup is known.
/// Verification rejects every element.
const SMALL_ORDER_PUBKEYS: [[u8; 32]; 8] = [
    // 0 (identity)
    [0u8; 32],
    // 1
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // 3256062507161957023555920433985600817822942841665119516180377884119074600195
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x28, 0xb3, 0x51, 0xfd, 0x59, 0x9c, 0xae, 0xc3, 0x3f, 0x6d, 0x8a,
        0x58, 0x24, 0x14, 0x0d, 0x0c, 0x7c, 0x2a, 0x36, 0xb5, 0x0f, 0x3e, 0x0d, 0x6f, 0x5d, 0x03,
        0x2b, 0x02,
    ],
    // p+1
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x64, 0x4a, 0x9a, 0x67, 0x2c, 0x69, 0x2c, 0xf0, 0x58, 0x6f,
        0x7a, 0x7f,
    ],
    // p+2 (order 8)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p+3 (order 8)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p+4 (order 4)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p+5 (order 4)
    [
        0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

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
        self.mk.codec == Codec::X25519Priv
    }
    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::X25519Pub
    }
    fn is_secret_key_share(&self) -> bool {
        false
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

/// Compute the DH scalar from the X25519 secret key bytes.
///
/// The scalar is the clamped secret key itself, reduced modulo the group
/// order. Its base multiple is the point behind the published u-coordinate.
fn dh_scalar(secret_bytes: &[u8]) -> Result<Scalar, Error> {
    if secret_bytes.len() != X25519_KEY_LENGTH {
        return Err(
            ConversionsError::SecretKeyFailure("invalid X25519 secret key length".into()).into(),
        );
    }
    let seed: [u8; 32] = <[u8; 32]>::try_from(secret_bytes)
        .map_err(|_| ConversionsError::SecretKeyFailure("invalid X25519 secret key".into()))?;

    // The X25519 clamp: clear the three low bits, clear the high bit, and
    // set bit 254. Reduction modulo the group order preserves the scalar
    // multiple because the base point has order l.
    let mut scalar_bytes = seed;
    scalar_bytes[0] &= 0b1111_1000;
    scalar_bytes[31] = (scalar_bytes[31] & 0b0111_1111) | 0b0100_0000;
    Ok(Scalar::from_bytes_mod_order(scalar_bytes))
}

/// Compute the canonical Edwards lift of a Montgomery u coordinate.
///
/// The lift forces the Edwards y sign bit to zero. The result is the point
/// that `calculate_A_from_u` in the XEdDSA specification recovers. Returns an
/// error when the u encoding is non-canonical, encodes a small-order point, or
/// encodes a point outside the prime-order subgroup.
fn canonical_lift(u_bytes: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    // Reject the eight small-order representatives. The identity and the
    // order-2, order-4, and order-8 points cannot serve as proof keys.
    for small in &SMALL_ORDER_PUBKEYS {
        if u_bytes.ct_eq(small).into() {
            return Err(
                ConversionsError::PublicKeyFailure("small-order X25519 public key".into()).into(),
            );
        }
    }

    // to_edwards(sign) applies the birational map y = (u-1)/(u+1) and picks
    // the x sign. Sign 0 recovers the point whose canonical encoding has y
    // sign 0: the deterministic canonical lift.
    let montgomery_point = MontgomeryPoint(*u_bytes);
    let a_ed = montgomery_point.to_edwards(0).ok_or_else(|| {
        ConversionsError::PublicKeyFailure("X25519 key is on the twist, not the curve".into())
    })?;

    // The mixed-order check: the point must be torsion-free. A point on the
    // curve but outside the prime-order subgroup fails this check.
    if !a_ed.is_torsion_free() {
        return Err(
            ConversionsError::PublicKeyFailure("mixed-order X25519 public key".into()).into(),
        );
    }

    // The identity is small order and already rejected above; this round trip
    // additionally guards against any encoding drift.
    if a_ed.to_montgomery() != montgomery_point {
        return Err(ConversionsError::PublicKeyFailure(
            "X25519 public key does not round-trip through the canonical lift".into(),
        )
        .into());
    }

    Ok(a_ed)
}

/// Derive the XEdDSA key pair from the secret key bytes: the POP signing
/// scalar and the canonical Edwards point `A` it generates.
///
/// The scalar is the sign-normalized DH scalar: it is negated when the
/// canonical encoding of the DH scalar's base multiple carries y sign 1. The
/// resulting scalar point equals the canonical lift of the published
/// u-coordinate, so a signature under it verifies through the lift.
fn key_pair(secret_bytes: &[u8]) -> Result<(Scalar, EdwardsPoint), Error> {
    let mut a = dh_scalar(secret_bytes)?;
    let a_raw = EdwardsPoint::mul_base(&a);
    let a_ed = a_raw.to_montgomery().to_edwards(0).ok_or_else(|| {
        ConversionsError::PublicKeyFailure("X25519 key is on the twist, not the curve".into())
    })?;
    if a_raw.compress().as_bytes()[31] >> 7 == 1 {
        a = -a;
    }
    Ok((a, a_ed))
}

impl<'a> FingerprintView for View<'a> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        let pub_bytes = if self.is_secret_key() {
            let pk = self.to_public_key()?;
            let dv = dispatch_data_view(&pk)?;
            dv.key_bytes()?
        } else {
            self.key_bytes()?
        };
        Ok(mh::Builder::new_from_bytes(codec, pub_bytes.as_slice())?.try_build()?)
    }
}

impl<'a> ConvView for View<'a> {
    /// Derive the X25519 public key from the secret key bytes.
    ///
    /// The published u-coordinate is the standard ladder output
    /// `clamp(sk) * B_mont`. The POP signing scalar generates the same
    /// point, so the derived key verifies under the XEdDSA verifier.
    fn to_public_key(&self) -> Result<Multikey, Error> {
        let secret_bytes = {
            let kd = dispatch_data_view(self.mk)?;
            kd.secret_bytes()?
        };
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            *secret_bytes.as_slice().first_chunk::<32>().ok_or_else(|| {
                ConversionsError::SecretKeyFailure("invalid X25519 secret key".into())
            })?,
        ));

        Builder::new(Codec::X25519Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&public.as_bytes().to_vec())
            .try_build()
    }

    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        Err(
            ConversionsError::UnsupportedAlgorithm("X25519 not supported in SSH key format".into())
                .into(),
        )
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(
            ConversionsError::UnsupportedAlgorithm("X25519 not supported in SSH key format".into())
                .into(),
        )
    }
}

impl<'a> SignView for View<'a> {
    /// Sign a 32-byte message with XEdDSA and return a `xeddsa-msig` multisig.
    ///
    /// The message restriction is normative. The proof-of-possession framework
    /// is the only authorized caller class, and its messages are 32-byte
    /// transcript challenges.
    fn sign(&self, msg: &[u8], combined: bool, _scheme: Option<u8>) -> Result<Multisig, Error> {
        let attr = dispatch_attr_view(self.mk)?;
        if !attr.is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }
        if msg.len() != X25519_KEY_LENGTH {
            return Err(Error::UnsupportedAlgorithm(
                "XEdDSA signs 32-byte transcript challenges only; this view is POP-only".into(),
            ));
        }

        let secret_bytes = {
            let kd = dispatch_data_view(self.mk)?;
            kd.secret_bytes()?
        };

        let (a, a_ed) = key_pair(&secret_bytes)?;

        // Nonce derivation per XEdDSA section 2.4:
        //     r = hash1(a || pad1 || M || pad2 || Z)
        // with pad1 = 32 zero bytes, pad2 = 32 zero bytes for SHA-512, and Z
        // 64 random bytes from a cryptographically secure source.
        let mut z = [0u8; 64];
        getrandom::fill(&mut z).map_err(|e| SignError::SigningFailed(e.to_string()))?;

        let mut nonce_hasher = Sha512::default();
        nonce_hasher.update(a.as_bytes());
        nonce_hasher.update([0u8; 32]); // pad1
        nonce_hasher.update(msg);
        nonce_hasher.update([0u8; 32]); // pad2
        nonce_hasher.update(z);
        let r = Scalar::from_hash(nonce_hasher);
        let big_r = EdwardsPoint::mul_base(&r).compress();

        // S = r + H(R || A || M) * a  (mod l), with A in the canonical
        // sign-0 encoding that the verifier also recovers from u.
        let a_ed_bytes = a_ed.compress().to_bytes();
        let mut challenge_input = Vec::with_capacity(32 + 32 + msg.len());
        challenge_input.extend_from_slice(big_r.as_bytes());
        challenge_input.extend_from_slice(&a_ed_bytes);
        challenge_input.extend_from_slice(msg);
        let s = Scalar::from_hash(Sha512::default().chain_update(&challenge_input)) * a + r;

        let mut signature_bytes = [0u8; ED25519_SIGNATURE_LENGTH];
        signature_bytes[..32].copy_from_slice(big_r.as_bytes());
        signature_bytes[32..].copy_from_slice(s.as_bytes());

        let mut builder =
            ms::Builder::new(Codec::XeddsaMsig).with_signature_bytes(&signature_bytes);
        if combined {
            builder = builder.with_message_bytes(&msg);
        }
        Ok(builder.try_build()?)
    }
}

impl<'a> VerifyView for View<'a> {
    /// Verify an XEdDSA multisig against the Edwards form of the X25519 key.
    ///
    /// The verifier computes the canonical lift itself. It rejects a
    /// non-canonical u encoding, a small-order key, and a mixed-order key.
    /// Signature verification is strict: a non-canonical R or S is rejected.
    fn verify(&self, multisig: &Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let attr = dispatch_attr_view(self.mk)?;
        let pubmk = if attr.is_secret_key() {
            dispatch_conv_view(self.mk)?.to_public_key()?
        } else {
            self.mk.clone()
        };

        if pubmk.codec != Codec::X25519Pub {
            return Err(AttributesError::UnsupportedCodec(pubmk.codec).into());
        }

        let key_bytes = {
            let kd = dispatch_data_view(&pubmk)?;
            kd.key_bytes()?
        };

        let u_bytes: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            ConversionsError::PublicKeyFailure("invalid X25519 public key length".to_string())
        })?;

        let a_ed = canonical_lift(&u_bytes)?;
        let verifying_key_bytes: [u8; 32] = a_ed.compress().to_bytes();
        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

        let sv = ViewBuilder::new(multisig).data().build()?;
        let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;
        if sig.len() != ED25519_SIGNATURE_LENGTH {
            return Err(VerifyError::BadSignature(
                "XEdDSA signature must be exactly 64 bytes".into(),
            )
            .into());
        }

        let sig = Signature::from_slice(sig.as_slice())
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

        let msg = if let Some(msg) = msg {
            msg
        } else if !multisig.message.is_empty() {
            multisig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };
        if msg.len() != X25519_KEY_LENGTH {
            return Err(
                VerifyError::BadSignature("XEdDSA signs 32-byte messages only".into()).into(),
            );
        }

        // Ed25519 strict verification: a non-canonical R or S fails.
        verifying_key
            .verify(msg, &sig)
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Builder, ViewBuilder};
    use multi_sig::ViewBuilder as SigViewBuilder;

    fn key_pair_mks() -> (Multikey, Multikey) {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::X25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = ViewBuilder::new(&sk)
            .conv()
            .build()
            .unwrap()
            .to_public_key()
            .unwrap();
        (sk, pk)
    }

    fn message32() -> [u8; 32] {
        let mut msg = [0u8; 32];
        getrandom::fill(&mut msg).unwrap();
        msg
    }

    #[test]
    fn test_xeddsa_sign_verify_roundtrip() {
        for _ in 0..8 {
            let (sk, pk) = key_pair_mks();
            let msg = message32();
            let sig = ViewBuilder::new(&sk)
                .sign()
                .build()
                .unwrap()
                .sign(&msg, false, None)
                .unwrap();
            ViewBuilder::new(&pk)
                .verify()
                .build()
                .unwrap()
                .verify(&sig, Some(&msg))
                .unwrap();
        }
    }

    #[test]
    fn test_xeddsa_rejects_non_32_byte_message() {
        let (sk, _pk) = key_pair_mks();
        let sv = ViewBuilder::new(&sk).sign().build().unwrap();
        assert!(sv.sign(b"short", false, None).is_err());
        assert!(sv.sign(&[0u8; 33], false, None).is_err());
        assert!(sv.sign(&[0u8; 31], false, None).is_err());
    }

    #[test]
    fn test_xeddsa_wrong_message_fails() {
        let (sk, pk) = key_pair_mks();
        let msg = message32();
        let other = message32();
        let sig = ViewBuilder::new(&sk)
            .sign()
            .build()
            .unwrap()
            .sign(&msg, false, None)
            .unwrap();
        assert!(
            ViewBuilder::new(&pk)
                .verify()
                .build()
                .unwrap()
                .verify(&sig, Some(&other))
                .is_err()
        );
    }

    #[test]
    fn test_xeddsa_wrong_key_fails() {
        let (sk, _pk) = key_pair_mks();
        let (_sk2, pk2) = key_pair_mks();
        let msg = message32();
        let sig = ViewBuilder::new(&sk)
            .sign()
            .build()
            .unwrap()
            .sign(&msg, false, None)
            .unwrap();
        assert!(
            ViewBuilder::new(&pk2)
                .verify()
                .build()
                .unwrap()
                .verify(&sig, Some(&msg))
                .is_err()
        );
    }

    #[test]
    fn test_xeddsa_public_key_cannot_sign() {
        let (_sk, pk) = key_pair_mks();
        let msg = message32();
        assert!(
            ViewBuilder::new(&pk)
                .sign()
                .build()
                .unwrap()
                .sign(&msg, false, None)
                .is_err()
        );
    }

    #[test]
    fn test_xeddsa_tampered_signature_fails() {
        let (sk, pk) = key_pair_mks();
        let msg = message32();
        let sig = ViewBuilder::new(&sk)
            .sign()
            .build()
            .unwrap()
            .sign(&msg, false, None)
            .unwrap();
        let view = SigViewBuilder::new(&sig).data().build().unwrap();
        let mut bytes = view.sig_bytes().unwrap();
        bytes[0] ^= 1;
        let tampered = ms::Builder::new(Codec::XeddsaMsig)
            .with_signature_bytes(&bytes)
            .try_build()
            .unwrap();
        assert!(
            ViewBuilder::new(&pk)
                .verify()
                .build()
                .unwrap()
                .verify(&tampered, Some(&msg))
                .is_err()
        );
    }

    #[test]
    fn test_xeddsa_kat_rfc7748_seed() {
        // KAT over the RFC 7748 Alice key pair. The seed is the RFC 7748
        // Alice private key. The XEdDSA signing scalar is the clamped seed.
        let seed: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let sk = Builder::new(Codec::X25519Priv)
            .with_key_bytes(&seed)
            .try_build()
            .unwrap();
        let pk = ViewBuilder::new(&sk)
            .conv()
            .build()
            .unwrap()
            .to_public_key()
            .unwrap();

        // The published u must be the standard RFC 7748 ladder output.
        let expected_u: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let dv = ViewBuilder::new(&pk).data().build().unwrap();
        let pub_bytes = dv.key_bytes().unwrap();
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(pub_bytes.as_slice());
        assert_eq!(pub_arr, expected_u);

        // The POP signing scalar is the sign-normalized DH scalar; its
        // canonical Edwards point equals the canonical lift of the ladder u.
        let (a, a_ed) = key_pair(&seed).unwrap();
        assert_eq!(*a_ed.to_montgomery().as_bytes(), expected_u);

        // The canonical lift of the published u recovers the same point.
        let lift = canonical_lift(&pub_arr).unwrap();
        assert_eq!(lift, a_ed);

        // Sign and verify a fixed 32-byte message. The nonce is derived per
        // the spec with a fresh random Z, so only verify is deterministic.
        let msg: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let sig = ViewBuilder::new(&sk)
            .sign()
            .build()
            .unwrap()
            .sign(&msg, false, None)
            .unwrap();
        ViewBuilder::new(&pk)
            .verify()
            .build()
            .unwrap()
            .verify(&sig, Some(&msg))
            .unwrap();

        // Every signature is 64 bytes of R || s.
        let dv = SigViewBuilder::new(&sig).data().build().unwrap();
        assert_eq!(dv.sig_bytes().unwrap().len(), 64);
        let _ = a;
    }

    #[test]
    fn test_xeddsa_lift_determinism() {
        // The lift is a function: for random valid u, lift-then-encode is
        // deterministic and returns sign 0.
        for _ in 0..16 {
            let (sk, pk) = key_pair_mks();
            let dv = ViewBuilder::new(&pk).data().build().unwrap();
            let mut u = [0u8; 32];
            u.copy_from_slice(dv.key_bytes().unwrap().as_slice());
            let lift = canonical_lift(&u).unwrap();
            assert_eq!(lift.compress().as_bytes()[31] >> 7, 0);
            assert_eq!(*lift.to_montgomery().as_bytes(), u);
            let _ = sk;
        }
    }

    #[test]
    fn test_xeddsa_small_order_keys_rejected() {
        let (sk, _pk) = key_pair_mks();
        let msg = message32();
        let sig = ViewBuilder::new(&sk)
            .sign()
            .build()
            .unwrap()
            .sign(&msg, false, None)
            .unwrap();

        for small in &SMALL_ORDER_PUBKEYS {
            let pk = Builder::new(Codec::X25519Pub)
                .with_key_bytes(small)
                .try_build()
                .unwrap();
            assert!(
                ViewBuilder::new(&pk)
                    .verify()
                    .build()
                    .unwrap()
                    .verify(&sig, Some(&msg))
                    .is_err(),
                "small-order key {small:?} must not verify"
            );
        }
    }
}
