// SPDX-License-Identifier: Apache-2.0
//! Split a private [`Multikey`] into `n` threshold-`t` verifiable shares and
//! recombine them. This only splits/recombines static key material — it does
//! not perform threshold signing.
//!
//! Scheme selection per key family:
//! * **Feldman VSS over the curve scalar field** (verifiable, with commitments)
//!   for single-scalar keys: secp256k1, P-256, P-384, P-521, and BLS12-381
//!   G1/G2 — so every elliptic-curve key, BLS included, produces commitment-
//!   verifiable shares uniformly.
//! * **gf256 byte-sharing** for RSA and the post-quantum families (ML-DSA,
//!   ML-KEM, SLH-DSA, FN-DSA, MAYO, SNTRUP, FrodoKEM, Classic McEliece) and the
//!   hybrids — opaque byte secrets that round-trip exactly.
//! * **Dual** for Ed25519/X25519: a gf256 share of the 32-byte seed (exact,
//!   functional restore) plus a Feldman scalar share with commitments (mirrors
//!   the ECC keys, threshold-signing-ready). Both are stored per share.
//!
//! A share is a [`Codec::KeySplitShare`] `Multikey` whose [`AttrId::KeyData`] is
//! the CBOR-encoded share payload, so shares serialize to CBOR/JSON through the
//! normal Multikey encoders.

use crate::mk::Attributes;
use crate::{AttrId, Builder, Error, Multikey, Views};
use blsful::inner_types::{G1Projective, G2Projective, Scalar as BlsScalar};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar as DalekScalar};
use elliptic_curve::ff::PrimeField;
use elliptic_curve::group::GroupEncoding;
use multi_codec::Codec;
use multi_util::CodecInfo;
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use vsss_rs::{
    DefaultShare, FeldmanVerifierSet, Gf256, IdentifierPrimeField, ReadableShareSet,
    ShareVerifierGroup, ValueGroup, feldman,
};
use zeroize::Zeroizing;

type Ds<F> = DefaultShare<IdentifierPrimeField<F>, IdentifierPrimeField<F>>;

fn err<E: core::fmt::Display>(e: E) -> Error {
    Error::KeySplit(e.to_string())
}

/// Serialize a value to CBOR bytes using `ciborium` (replaces the
/// unmaintained `serde_cbor` dependency).
fn cbor_to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(err)?;
    Ok(buf)
}

/// Deserialize a value from CBOR bytes using `ciborium`.
fn cbor_from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    ciborium::from_reader(bytes).map_err(err)
}

/// Sharing scheme tag stored in each share payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Scheme {
    Feldman,
    Gf256,
}

/// The Feldman scalar share carried alongside an Ed25519/X25519 gf256 seed share.
#[derive(Clone, Serialize, Deserialize)]
struct DualPayload {
    identifier: Vec<u8>,
    value: Vec<u8>,
    verifiers: Vec<Vec<u8>>,
}

/// CBOR payload stored in a [`Codec::KeySplitShare`] Multikey's key data.
#[derive(Clone, Serialize, Deserialize)]
struct SharePayload {
    /// the original (split) key's codec, as its multicodec code
    codec: u64,
    threshold: u16,
    limit: u16,
    scheme: Scheme,
    identifier: Vec<u8>,
    value: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifiers: Option<Vec<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dual: Option<DualPayload>,
}

// ---- scalar helpers ---------------------------------------------------------

/// Decode a canonical scalar repr into a field element.
fn scalar<F: PrimeField>(bytes: &[u8]) -> Result<F, Error> {
    let mut repr = F::Repr::default();
    let r = repr.as_mut();
    if bytes.len() != r.len() {
        return Err(err("wrong scalar length"));
    }
    r.copy_from_slice(bytes);
    Option::<F>::from(F::from_repr(repr)).ok_or_else(|| err("non-canonical scalar"))
}

/// BLS scalars are big-endian in multikey but little-endian in `bls12_381_plus`.
fn bls_from_be<F: PrimeField>(be: &[u8]) -> Result<F, Error> {
    let mut le = be.to_vec();
    le.reverse();
    scalar::<F>(&le)
}

fn rev(mut v: Vec<u8>) -> Vec<u8> {
    v.reverse();
    v
}

fn wrapped_from_seed(secret: &[u8]) -> Result<DalekScalar, Error> {
    let seed: [u8; 32] = secret
        .try_into()
        .map_err(|_| err("ed25519/x25519 seed must be 32 bytes"))?;
    Ok(DalekScalar::from_bytes_mod_order(seed))
}

// ---- per-curve Feldman (monomorphized to avoid ShareVerifier ambiguity) -----

/// `(shares as (id, value) pairs, shared verifier commitment set)`.
type EccShares = (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>);

macro_rules! feldman_curve {
    ($split:ident, $combine:ident, $verify:ident, $f:ty, $g:ty) => {
        fn $split(
            secret: $f,
            threshold: usize,
            limit: usize,
            rng: impl CryptoRng,
        ) -> Result<EccShares, Error> {
            let (shares, verifiers) = feldman::split_secret::<Ds<$f>, ShareVerifierGroup<$g>>(
                threshold,
                limit,
                &IdentifierPrimeField(secret),
                None,
                rng,
            )
            .map_err(err)?;
            let vbytes: Vec<Vec<u8>> = verifiers
                .iter()
                .map(|v| AsRef::<[u8]>::as_ref(&<$g as GroupEncoding>::to_bytes(&v.0)).to_vec())
                .collect();
            let pairs = shares
                .iter()
                .map(|s| {
                    let id = <$f as PrimeField>::to_repr(&s.identifier.0);
                    let val = <$f as PrimeField>::to_repr(&s.value.0);
                    (
                        AsRef::<[u8]>::as_ref(&id).to_vec(),
                        AsRef::<[u8]>::as_ref(&val).to_vec(),
                    )
                })
                .collect();
            Ok((pairs, vbytes))
        }

        fn $combine(pairs: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>, Error> {
            let ds: Vec<Ds<$f>> = pairs
                .iter()
                .map(|(i, v)| {
                    Ok::<_, Error>(DefaultShare {
                        identifier: IdentifierPrimeField(scalar::<$f>(i)?),
                        value: IdentifierPrimeField(scalar::<$f>(v)?),
                    })
                })
                .collect::<Result<_, _>>()?;
            let secret: IdentifierPrimeField<$f> = ds.combine().map_err(err)?;
            let repr = <$f as PrimeField>::to_repr(&secret.0);
            Ok(AsRef::<[u8]>::as_ref(&repr).to_vec())
        }

        fn $verify(id: &[u8], val: &[u8], vb: &[Vec<u8>]) -> Result<(), Error> {
            let share: Ds<$f> = DefaultShare {
                identifier: IdentifierPrimeField(scalar::<$f>(id)?),
                value: IdentifierPrimeField(scalar::<$f>(val)?),
            };
            let verifiers: Vec<ShareVerifierGroup<$g>> = vb
                .iter()
                .map(|b| {
                    let mut repr = <$g as GroupEncoding>::Repr::default();
                    if AsRef::<[u8]>::as_ref(&repr).len() != b.len() {
                        return Err(err("bad verifier length"));
                    }
                    AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(b);
                    Option::<$g>::from(<$g as GroupEncoding>::from_bytes(&repr))
                        .map(ValueGroup)
                        .ok_or_else(|| err("bad verifier"))
                })
                .collect::<Result<_, _>>()?;
            verifiers
                .verify_share(&share)
                .map_err(|_| err("feldman verification failed"))
        }
    };
}

feldman_curve!(
    split_k256,
    combine_k256,
    verify_k256,
    k256::Scalar,
    k256::ProjectivePoint
);
feldman_curve!(
    split_p256,
    combine_p256,
    verify_p256,
    p256::Scalar,
    p256::ProjectivePoint
);
feldman_curve!(
    split_p384,
    combine_p384,
    verify_p384,
    p384::Scalar,
    p384::ProjectivePoint
);
feldman_curve!(
    split_p521,
    combine_p521,
    verify_p521,
    p521::Scalar,
    p521::ProjectivePoint
);
feldman_curve!(
    split_25519,
    combine_25519,
    verify_25519,
    DalekScalar,
    RistrettoPoint
);
feldman_curve!(
    split_blsg1,
    combine_blsg1,
    verify_blsg1,
    BlsScalar,
    G1Projective
);
feldman_curve!(
    split_blsg2,
    combine_blsg2,
    verify_blsg2,
    BlsScalar,
    G2Projective
);

fn is_feldman_codec(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::Secp256K1Priv
            | Codec::P256Priv
            | Codec::P384Priv
            | Codec::P521Priv
            | Codec::Ed25519Priv
            | Codec::X25519Priv
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G2Priv
    )
}

fn ecc_split(
    codec: Codec,
    secret: &[u8],
    t: usize,
    n: usize,
    rng: impl CryptoRng,
) -> Result<EccShares, Error> {
    match codec {
        Codec::Secp256K1Priv => split_k256(scalar::<k256::Scalar>(secret)?, t, n, rng),
        Codec::P256Priv => split_p256(scalar::<p256::Scalar>(secret)?, t, n, rng),
        Codec::P384Priv => split_p384(scalar::<p384::Scalar>(secret)?, t, n, rng),
        Codec::P521Priv => split_p521(scalar::<p521::Scalar>(secret)?, t, n, rng),
        Codec::Ed25519Priv | Codec::X25519Priv => {
            split_25519(wrapped_from_seed(secret)?, t, n, rng)
        }
        Codec::Bls12381G1Priv => split_blsg1(bls_from_be::<BlsScalar>(secret)?, t, n, rng),
        Codec::Bls12381G2Priv => split_blsg2(bls_from_be::<BlsScalar>(secret)?, t, n, rng),
        _ => Err(err("unsupported curve codec")),
    }
}

fn ecc_combine(codec: Codec, pairs: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::Secp256K1Priv => combine_k256(pairs),
        Codec::P256Priv => combine_p256(pairs),
        Codec::P384Priv => combine_p384(pairs),
        Codec::P521Priv => combine_p521(pairs),
        Codec::Ed25519Priv | Codec::X25519Priv => combine_25519(pairs),
        Codec::Bls12381G1Priv => combine_blsg1(pairs).map(rev),
        Codec::Bls12381G2Priv => combine_blsg2(pairs).map(rev),
        _ => Err(err("unsupported curve codec")),
    }
}

fn ecc_verify(codec: Codec, id: &[u8], val: &[u8], vb: &[Vec<u8>]) -> Result<(), Error> {
    match codec {
        Codec::Secp256K1Priv => verify_k256(id, val, vb),
        Codec::P256Priv => verify_p256(id, val, vb),
        Codec::P384Priv => verify_p384(id, val, vb),
        Codec::P521Priv => verify_p521(id, val, vb),
        Codec::Ed25519Priv | Codec::X25519Priv => verify_25519(id, val, vb),
        Codec::Bls12381G1Priv => verify_blsg1(id, val, vb),
        Codec::Bls12381G2Priv => verify_blsg2(id, val, vb),
        _ => Err(err("unsupported curve codec")),
    }
}

// ---- gf256 byte path --------------------------------------------------------

fn gf256_split(
    secret: &[u8],
    t: usize,
    n: usize,
    rng: impl CryptoRng,
) -> Result<Vec<(u8, Vec<u8>)>, Error> {
    let raw = Gf256::split_array(t, n, secret, rng).map_err(err)?;
    raw.into_iter()
        .map(|inner| {
            let (id, val) = inner
                .split_first()
                .ok_or_else(|| err("empty gf256 share"))?;
            Ok((*id, val.to_vec()))
        })
        .collect()
}

fn gf256_combine(rows: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, Error> {
    let full: Vec<Vec<u8>> = rows
        .iter()
        .map(|(id, val)| {
            let mut r = Vec::with_capacity(1 + val.len());
            r.push(*id);
            r.extend_from_slice(val);
            r
        })
        .collect();
    Gf256::combine_array(&full).map_err(err)
}

// ---- payload construction / share wrapping ----------------------------------

fn build_payloads(
    codec: Codec,
    secret: &[u8],
    t: usize,
    n: usize,
    mut rng: impl CryptoRng,
) -> Result<Vec<SharePayload>, Error> {
    let ccode: u64 = codec.into();
    if matches!(codec, Codec::Ed25519Priv | Codec::X25519Priv) {
        // dual: gf256 seed share (exact restore) + Feldman scalar share
        let seed = gf256_split(secret, t, n, &mut rng)?;
        let (pairs, verifiers) = ecc_split(codec, secret, t, n, &mut rng)?;
        Ok(seed
            .into_iter()
            .zip(pairs)
            .map(|((id, val), (fid, fval))| SharePayload {
                codec: ccode,
                threshold: t as u16,
                limit: n as u16,
                scheme: Scheme::Gf256,
                identifier: vec![id],
                value: val,
                verifiers: None,
                dual: Some(DualPayload {
                    identifier: fid,
                    value: fval,
                    verifiers: verifiers.clone(),
                }),
            })
            .collect())
    } else if is_feldman_codec(codec) {
        let (pairs, verifiers) = ecc_split(codec, secret, t, n, rng)?;
        Ok(pairs
            .into_iter()
            .map(|(id, val)| SharePayload {
                codec: ccode,
                threshold: t as u16,
                limit: n as u16,
                scheme: Scheme::Feldman,
                identifier: id,
                value: val,
                verifiers: Some(verifiers.clone()),
                dual: None,
            })
            .collect())
    } else {
        let rows = gf256_split(secret, t, n, rng)?;
        Ok(rows
            .into_iter()
            .map(|(id, val)| SharePayload {
                codec: ccode,
                threshold: t as u16,
                limit: n as u16,
                scheme: Scheme::Gf256,
                identifier: vec![id],
                value: val,
                verifiers: None,
                dual: None,
            })
            .collect())
    }
}

fn wrap_share(orig: &Multikey, payload: &SharePayload) -> Result<Multikey, Error> {
    let cbor = cbor_to_vec(payload)?;
    let mut attributes = Attributes::new();
    attributes.insert(AttrId::KeyData, Zeroizing::new(cbor));
    Ok(Multikey {
        codec: Codec::KeySplitShare,
        comment: orig.comment.clone(),
        attributes,
    })
}

fn unwrap_share(mk: &Multikey) -> Result<SharePayload, Error> {
    if mk.codec() != Codec::KeySplitShare {
        return Err(err("not a key-split share"));
    }
    let kd = mk
        .attributes
        .get(&AttrId::KeyData)
        .ok_or_else(|| err("share missing key data"))?;
    cbor_from_slice(kd.as_slice())
}

// ---- public API -------------------------------------------------------------

/// Split a private [`Multikey`] into `limit` shares, any `threshold` of which
/// recombine it. Returns one [`Codec::KeySplitShare`] Multikey per share.
pub fn split(
    mk: &Multikey,
    threshold: usize,
    limit: usize,
    rng: impl CryptoRng,
) -> Result<Vec<Multikey>, Error> {
    if threshold < 2 || threshold > limit || limit > 255 {
        return Err(err("need 2 <= threshold <= limit <= 255"));
    }
    let codec = mk.codec();
    let secret = mk.data_view()?.secret_bytes()?;
    let payloads = build_payloads(codec, &secret, threshold, limit, rng)?;
    payloads.iter().map(|p| wrap_share(mk, p)).collect()
}

/// Verify a single share's Feldman commitments (Feldman scheme, or the dual of
/// an Ed25519/X25519 seed share). gf256-only shares have nothing to verify.
pub fn verify_share(share: &Multikey) -> Result<(), Error> {
    let p = unwrap_share(share)?;
    let codec = Codec::try_from(p.codec).map_err(err)?;
    match p.scheme {
        Scheme::Feldman => {
            let vb = p
                .verifiers
                .as_deref()
                .ok_or_else(|| err("missing verifiers"))?;
            ecc_verify(codec, &p.identifier, &p.value, vb)
        }
        Scheme::Gf256 => {
            if let Some(d) = &p.dual {
                ecc_verify(codec, &d.identifier, &d.value, &d.verifiers)?;
            }
            Ok(())
        }
    }
}

/// Recombine [`Codec::KeySplitShare`] shares into the original private key. At
/// least `threshold` shares for the same key are required; Feldman shares are
/// verified before combining.
pub fn combine(shares: &[Multikey]) -> Result<Multikey, Error> {
    if shares.is_empty() {
        return Err(err("no shares supplied"));
    }
    let payloads: Vec<SharePayload> = shares.iter().map(unwrap_share).collect::<Result<_, _>>()?;
    let first = &payloads[0];
    if payloads
        .iter()
        .any(|p| p.codec != first.codec || p.scheme != first.scheme)
    {
        return Err(err("shares describe different keys"));
    }
    let codec = Codec::try_from(first.codec).map_err(err)?;

    let secret: Zeroizing<Vec<u8>> = match first.scheme {
        Scheme::Feldman => {
            for p in &payloads {
                let vb = p
                    .verifiers
                    .as_deref()
                    .ok_or_else(|| err("missing verifiers"))?;
                ecc_verify(codec, &p.identifier, &p.value, vb)?;
            }
            let pairs: Vec<(Vec<u8>, Vec<u8>)> = payloads
                .iter()
                .map(|p| (p.identifier.clone(), p.value.clone()))
                .collect();
            Zeroizing::new(ecc_combine(codec, &pairs)?)
        }
        Scheme::Gf256 => {
            for p in &payloads {
                if let Some(d) = &p.dual {
                    ecc_verify(codec, &d.identifier, &d.value, &d.verifiers)?;
                }
            }
            let rows: Vec<(u8, Vec<u8>)> = payloads
                .iter()
                .map(|p| {
                    Ok::<_, Error>((
                        *p.identifier.first().ok_or_else(|| err("bad gf256 id"))?,
                        p.value.clone(),
                    ))
                })
                .collect::<Result<_, _>>()?;
            Zeroizing::new(gf256_combine(&rows)?)
        }
    };

    Builder::new(codec)
        .with_key_bytes(&secret.as_slice())
        .try_build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mk;

    fn gen_key(codec: Codec) -> Multikey {
        Builder::new_from_random_bytes(codec, &mut rand::rng())
            .unwrap_or_else(|e| panic!("{codec:?} keygen: {e}"))
            .try_build()
            .unwrap_or_else(|e| panic!("{codec:?} build: {e}"))
    }

    fn secret(mk: &Multikey) -> Vec<u8> {
        mk.data_view().unwrap().secret_bytes().unwrap().to_vec()
    }

    /// Split → verify every share → combine a non-contiguous subset → assert the
    /// reconstructed key is byte-identical to the original. Run for both 2-of-3
    /// and 3-of-5 with disjoint/non-contiguous subsets.
    fn assert_roundtrip(codec: Codec) {
        let mk = gen_key(codec);
        let original = secret(&mk);

        // 2-of-3
        let shares =
            split(&mk, 2, 3, rand::rng()).unwrap_or_else(|e| panic!("{codec:?} split 2/3: {e}"));
        assert_eq!(shares.len(), 3, "{codec:?} share count");
        for s in &shares {
            assert_eq!(s.codec(), Codec::KeySplitShare, "{codec:?} share codec");
            verify_share(s).unwrap_or_else(|e| panic!("{codec:?} verify_share: {e}"));
        }
        // combine the non-contiguous subset {0, 2}
        let got = combine(&[shares[0].clone(), shares[2].clone()])
            .unwrap_or_else(|e| panic!("{codec:?} combine 2/3: {e}"));
        assert_eq!(secret(&got), original, "{codec:?} 2-of-3 exact roundtrip");
        assert_eq!(got.codec(), codec, "{codec:?} reconstructed codec");

        // 3-of-5 with the non-contiguous subset {1, 3, 4}
        let shares5 =
            split(&mk, 3, 5, rand::rng()).unwrap_or_else(|e| panic!("{codec:?} split 3/5: {e}"));
        assert_eq!(shares5.len(), 5, "{codec:?} share count 5");
        let got5 = combine(&[shares5[1].clone(), shares5[3].clone(), shares5[4].clone()])
            .unwrap_or_else(|e| panic!("{codec:?} combine 3/5: {e}"));
        assert_eq!(secret(&got5), original, "{codec:?} 3-of-5 exact roundtrip");
    }

    fn assert_all(codecs: &[Codec]) {
        for &c in codecs {
            assert_roundtrip(c);
        }
    }

    // ── Elliptic-curve + Ed25519 (KEY_CODECS = ed25519, secp256k1, bls-g1,
    //    bls-g2, p256, p384, p521). Ed25519 restores exactly via the dual. ──
    #[test]
    fn roundtrip_key_codecs() {
        assert_all(&mk::KEY_CODECS);
    }

    #[test]
    fn roundtrip_x25519() {
        assert_all(&mk::X25519_KEY_CODECS);
    }

    // ── RSA ──
    #[test]
    fn roundtrip_rsa() {
        assert_all(&mk::RSA_KEY_CODECS);
    }

    // ── Post-quantum signatures ──
    #[test]
    fn roundtrip_ml_dsa() {
        assert_all(&mk::ML_DSA_KEY_CODECS);
    }

    #[test]
    fn roundtrip_fn_dsa() {
        assert_all(&mk::FN_DSA_KEY_CODECS);
    }

    #[test]
    fn roundtrip_mayo() {
        assert_all(&mk::MAYO_KEY_CODECS);
    }

    #[test]
    fn roundtrip_slh_dsa() {
        assert_all(&mk::SLH_DSA_KEY_CODECS);
    }

    // ── Post-quantum KEMs ──
    #[test]
    fn roundtrip_ml_kem() {
        assert_all(&mk::ML_KEM_KEY_CODECS);
    }

    #[test]
    fn roundtrip_sntrup() {
        assert_all(&mk::SNTRUP_KEY_CODECS);
    }

    #[test]
    fn roundtrip_mceliece() {
        assert_all(&mk::MCELIECE_KEY_CODECS);
    }

    #[test]
    fn roundtrip_frodokem() {
        assert_all(&mk::FRODOKEM_KEY_CODECS);
    }

    // ── Hybrid (classical + post-quantum) keys → gf256 byte path ──
    #[test]
    fn roundtrip_hybrids() {
        assert_all(&mk::X25519_SNTRUP761_KEY_CODECS);
        assert_all(&mk::X25519_MLKEM768_KEY_CODECS);
        assert_all(&mk::ED25519_MAYO2_KEY_CODECS);
    }

    // ── Scheme/property checks ──
    #[test]
    fn ed25519_x25519_carry_verifiable_dual() {
        for &codec in &[Codec::Ed25519Priv, Codec::X25519Priv] {
            let shares = split(&gen_key(codec), 2, 4, rand::rng()).unwrap();
            for s in &shares {
                let p = unwrap_share(s).unwrap();
                assert_eq!(p.scheme, Scheme::Gf256, "{codec:?} primary is gf256 seed");
                let d = p.dual.as_ref().expect("dual present");
                assert!(!d.verifiers.is_empty(), "{codec:?} dual has commitments");
            }
        }
    }

    #[test]
    fn feldman_curves_emit_commitments() {
        for &codec in &[
            Codec::Secp256K1Priv,
            Codec::P256Priv,
            Codec::P384Priv,
            Codec::P521Priv,
            Codec::Bls12381G1Priv,
            Codec::Bls12381G2Priv,
        ] {
            let shares = split(&gen_key(codec), 2, 3, rand::rng()).unwrap();
            let p = unwrap_share(&shares[0]).unwrap();
            assert_eq!(p.scheme, Scheme::Feldman, "{codec:?}");
            assert!(p.verifiers.is_some(), "{codec:?} has Feldman commitments");
        }
    }

    // ── Serialization: a KeySplitShare is a Multikey; CBOR + JSON round-trip ──
    #[test]
    fn share_survives_cbor_and_json() {
        let mk = gen_key(Codec::P256Priv);
        let original = secret(&mk);
        let shares = split(&mk, 2, 3, rand::rng()).unwrap();

        let cbor: Vec<Vec<u8>> = shares.iter().map(|s| cbor_to_vec(s).unwrap()).collect();
        let from_cbor: Vec<Multikey> = cbor.iter().map(|b| cbor_from_slice(b).unwrap()).collect();
        assert_eq!(
            secret(&combine(&from_cbor[0..2]).unwrap()),
            original,
            "cbor roundtrip"
        );

        let json: Vec<Vec<u8>> = shares
            .iter()
            .map(|s| serde_json::to_vec(s).unwrap())
            .collect();
        let from_json: Vec<Multikey> = json
            .iter()
            .map(|b| serde_json::from_slice(b).unwrap())
            .collect();
        assert_eq!(
            secret(&combine(&from_json[0..2]).unwrap()),
            original,
            "json roundtrip"
        );
    }

    // ── Negative tests ──
    #[test]
    fn tampered_feldman_share_fails_verify() {
        let mk = gen_key(Codec::P256Priv);
        let shares = split(&mk, 2, 3, rand::rng()).unwrap();
        let mut p = unwrap_share(&shares[0]).unwrap();
        p.value[0] ^= 0xff;
        let bad = wrap_share(&mk, &p).unwrap();
        assert!(
            verify_share(&bad).is_err(),
            "tampered Feldman share must fail"
        );
    }

    #[test]
    fn tampered_dual_fails_verify() {
        let mk = gen_key(Codec::Ed25519Priv);
        let shares = split(&mk, 2, 3, rand::rng()).unwrap();
        let mut p = unwrap_share(&shares[0]).unwrap();
        p.dual.as_mut().unwrap().value[0] ^= 0xff;
        let bad = wrap_share(&mk, &p).unwrap();
        assert!(verify_share(&bad).is_err(), "tampered dual must fail");
    }

    #[test]
    fn below_threshold_does_not_recover() {
        let mk = gen_key(Codec::P256Priv);
        let original = secret(&mk);
        let shares = split(&mk, 3, 5, rand::rng()).unwrap();
        if let Ok(got) = combine(&shares[0..2]) {
            assert_ne!(secret(&got), original, "under-threshold leaked the secret");
        }
    }

    #[test]
    fn mixed_and_empty_and_public_rejected() {
        let a = split(&gen_key(Codec::P256Priv), 2, 3, rand::rng()).unwrap();
        let b = split(&gen_key(Codec::Secp256K1Priv), 2, 3, rand::rng()).unwrap();
        assert!(
            combine(&[a[0].clone(), b[0].clone()]).is_err(),
            "mixed codecs"
        );
        assert!(combine(&[]).is_err(), "empty set");
        let pk = gen_key(Codec::P256Priv)
            .conv_view()
            .unwrap()
            .to_public_key()
            .unwrap();
        assert!(split(&pk, 2, 3, rand::rng()).is_err(), "public key");
    }

    #[test]
    fn invalid_params_rejected() {
        let mk = gen_key(Codec::P256Priv);
        assert!(split(&mk, 1, 3, rand::rng()).is_err(), "threshold < 2");
        assert!(split(&mk, 4, 3, rand::rng()).is_err(), "threshold > limit");
    }
}
