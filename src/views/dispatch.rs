// SPDX-License-Identifier: Apache-2.0

//! The shared Multikey view dispatch core.
//!
//! One constructor function per view kind dispatches on the Multikey codec
//! exactly as the original `impl Views for Multikey` bodies did, so the
//! deprecated `Views` shim and the `ViewBuilder` share one implementation.

#[cfg(feature = "xmss")]
use crate::views::xmss;
#[cfg(feature = "deprecated")]
use crate::views::{classic_mceliece, x25519_mceliece348864};
#[cfg(feature = "lamport")]
use crate::views::{lamport, lamport_merkle};
use crate::{
    AttrId, AttrView, CipherAttrView, CipherView, ConvView, DataView, Error, FingerprintView,
    KdfAttrView, KdfView, MerkleStateView, Multikey, OpenView, SealView, SignView,
    ThresholdAttrView, ThresholdDisclosureView, ThresholdKeyView, ThresholdView, VerifyView,
    error::{AttributesError, CipherError, ConversionsError, KdfError, SealError},
    views::{
        bcrypt, bls12381, bls12381_g1_fndsa512, bls12381_g1_mayo1, bls12381_g1_mayo2,
        bls12381_g1_mldsa65, chacha20, ed25519, ed25519_fndsa512, ed25519_mayo2, ed25519_mldsa65,
        fn_dsa, frodokem, mayo, ml_dsa, ml_kem, nist_p, rsa, secp256k1, slh_dsa, sntrup,
        threshold_meta, x25519, x25519_frodokem640, x25519_mlkem768, x25519_sntrup761, xeddsa,
    },
};
use multi_codec::Codec;
/// Builds the basic-attributes view for the viewed Multikey.
pub(crate) fn dispatch_attr_view<'a>(mk: &'a Multikey) -> Result<Box<dyn AttrView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1PrivShare
        | Codec::Bls12381G1Priv
        | Codec::Bls12381G1Pub
        | Codec::Bls12381G1PubShare
        | Codec::Bls12381G2PrivShare
        | Codec::Bls12381G2Priv
        | Codec::Bls12381G2Pub
        | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(mk)?)),
        Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(mk)?)),
        Codec::Secp256K1Pub | Codec::Secp256K1Priv => Ok(Box::new(secp256k1::View::try_from(mk)?)),
        Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(mk)?)),
        Codec::SlhDsaSha2128FPub
        | Codec::SlhDsaSha2128SPub
        | Codec::SlhDsaSha2192FPub
        | Codec::SlhDsaSha2192SPub
        | Codec::SlhDsaSha2256FPub
        | Codec::SlhDsaSha2256SPub
        | Codec::SlhDsaShake128FPub
        | Codec::SlhDsaShake128SPub
        | Codec::SlhDsaShake192FPub
        | Codec::SlhDsaShake192SPub
        | Codec::SlhDsaShake256FPub
        | Codec::SlhDsaShake256SPub
        | Codec::SlhDsaSha2128FPriv
        | Codec::SlhDsaSha2128SPriv
        | Codec::SlhDsaSha2192FPriv
        | Codec::SlhDsaSha2192SPriv
        | Codec::SlhDsaSha2256FPriv
        | Codec::SlhDsaSha2256SPriv
        | Codec::SlhDsaShake128FPriv
        | Codec::SlhDsaShake128SPriv
        | Codec::SlhDsaShake192FPriv
        | Codec::SlhDsaShake192SPriv
        | Codec::SlhDsaShake256FPriv
        | Codec::SlhDsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(mk)?)),
        Codec::MlDsa65Pub | Codec::MlDsa65Priv | Codec::MlDsa87Pub | Codec::MlDsa87Priv => {
            Ok(Box::new(ml_dsa::View::try_from(mk)?))
        }
        Codec::Mayo1Pub
        | Codec::Mayo1Priv
        | Codec::Mayo2Pub
        | Codec::Mayo2Priv
        | Codec::Mayo3Pub
        | Codec::Mayo3Priv
        | Codec::Mayo5Pub
        | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(mk)?)),
        Codec::FnDsa512Pub | Codec::FnDsa512Priv | Codec::FnDsa1024Pub | Codec::FnDsa1024Priv => {
            Ok(Box::new(fn_dsa::View::try_from(mk)?))
        }
        Codec::Mlkem768Pub | Codec::Mlkem768Priv | Codec::Mlkem1024Pub | Codec::Mlkem1024Priv => {
            Ok(Box::new(ml_kem::View::try_from(mk)?))
        }
        Codec::Sntrup761Pub
        | Codec::Sntrup761Priv
        | Codec::Sntrup857Pub
        | Codec::Sntrup857Priv
        | Codec::Sntrup953Pub
        | Codec::Sntrup953Priv
        | Codec::Sntrup1013Pub
        | Codec::Sntrup1013Priv
        | Codec::Sntrup1277Pub
        | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(mk)?)),
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
            Ok(Box::new(classic_mceliece::View::try_from(mk)?))
        }
        Codec::FrodoKem640AesPub
        | Codec::FrodoKem640AesPriv
        | Codec::FrodoKem976AesPub
        | Codec::FrodoKem976AesPriv
        | Codec::FrodoKem1344AesPub
        | Codec::FrodoKem1344AesPriv
        | Codec::FrodoKem640ShakePub
        | Codec::FrodoKem640ShakePriv
        | Codec::FrodoKem976ShakePub
        | Codec::FrodoKem976ShakePriv
        | Codec::FrodoKem1344ShakePub
        | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(mk)?)),
        Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(mk)?)),
        Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
            Ok(Box::new(x25519_sntrup761::View::try_from(mk)?))
        }
        Codec::X25519Frodokem640AesPub
        | Codec::X25519Frodokem640AesPriv
        | Codec::X25519Frodokem640ShakePub
        | Codec::X25519Frodokem640ShakePriv => {
            Ok(Box::new(x25519_frodokem640::View::try_from(mk)?))
        }
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
            Ok(Box::new(x25519_mceliece348864::View::try_from(mk)?))
        }
        Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
            Ok(Box::new(x25519_mlkem768::View::try_from(mk)?))
        }
        Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
            Ok(Box::new(ed25519_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
            Ok(Box::new(ed25519_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
            Ok(Box::new(bls12381_g1_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
            Ok(Box::new(bls12381_g1_fndsa512::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
            Ok(Box::new(bls12381_g1_mayo1::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
            Ok(Box::new(bls12381_g1_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
            Ok(Box::new(ed25519_fndsa512::View::try_from(mk)?))
        }
        Codec::P256Pub
        | Codec::P256Priv
        | Codec::P384Pub
        | Codec::P384Priv
        | Codec::P521Pub
        | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(mk)?)),
        Codec::Rsa2048Pub
        | Codec::Rsa2048Priv
        | Codec::Rsa3072Pub
        | Codec::Rsa3072Priv
        | Codec::Rsa4096Pub
        | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Pub
        | Codec::LamportSha3256Priv
        | Codec::LamportSha3256PrivShare
        | Codec::LamportSha3384Pub
        | Codec::LamportSha3384Priv
        | Codec::LamportSha3384PrivShare
        | Codec::LamportSha3512Pub
        | Codec::LamportSha3512Priv
        | Codec::LamportSha3512PrivShare
        | Codec::LamportSha2256Pub
        | Codec::LamportSha2256Priv
        | Codec::LamportSha2256PrivShare
        | Codec::LamportSha2384Pub
        | Codec::LamportSha2384Priv
        | Codec::LamportSha2384PrivShare
        | Codec::LamportSha2512Pub
        | Codec::LamportSha2512Priv
        | Codec::LamportSha2512PrivShare
        | Codec::LamportBlake2B512Pub
        | Codec::LamportBlake2B512Priv
        | Codec::LamportBlake2B512PrivShare
        | Codec::LamportBlake2S256Pub
        | Codec::LamportBlake2S256Priv
        | Codec::LamportBlake2S256PrivShare
        | Codec::LamportBlake3256Pub
        | Codec::LamportBlake3256Priv
        | Codec::LamportBlake3256PrivShare
        | Codec::LamportShake128Pub
        | Codec::LamportShake128Priv
        | Codec::LamportShake128PrivShare
        | Codec::LamportShake256Pub
        | Codec::LamportShake256Priv
        | Codec::LamportShake256PrivShare => Ok(Box::new(lamport::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3256Pub
        | Codec::LamportMerkleSha3256Priv
        | Codec::LamportMerkleSha3256PrivShare
        | Codec::LamportMerkleSha3384Pub
        | Codec::LamportMerkleSha3384Priv
        | Codec::LamportMerkleSha3384PrivShare
        | Codec::LamportMerkleSha3512Pub
        | Codec::LamportMerkleSha3512Priv
        | Codec::LamportMerkleSha3512PrivShare
        | Codec::LamportMerkleSha2256Pub
        | Codec::LamportMerkleSha2256Priv
        | Codec::LamportMerkleSha2256PrivShare
        | Codec::LamportMerkleSha2384Pub
        | Codec::LamportMerkleSha2384Priv
        | Codec::LamportMerkleSha2384PrivShare
        | Codec::LamportMerkleSha2512Pub
        | Codec::LamportMerkleSha2512Priv
        | Codec::LamportMerkleSha2512PrivShare
        | Codec::LamportMerkleBlake2B512Pub
        | Codec::LamportMerkleBlake2B512Priv
        | Codec::LamportMerkleBlake2B512PrivShare
        | Codec::LamportMerkleBlake2S256Pub
        | Codec::LamportMerkleBlake2S256Priv
        | Codec::LamportMerkleBlake2S256PrivShare
        | Codec::LamportMerkleBlake3256Pub
        | Codec::LamportMerkleBlake3256Priv
        | Codec::LamportMerkleBlake3256PrivShare
        | Codec::LamportMerkleShake128Pub
        | Codec::LamportMerkleShake128Priv
        | Codec::LamportMerkleShake128PrivShare
        | Codec::LamportMerkleShake256Pub
        | Codec::LamportMerkleShake256Priv
        | Codec::LamportMerkleShake256PrivShare => {
            Ok(Box::new(lamport_merkle::View::try_from(mk)?))
        }
        #[cfg(feature = "xmss")]
        Codec::XmssSha210256Pub
        | Codec::XmssSha210256Priv
        | Codec::XmssSha216256Pub
        | Codec::XmssSha216256Priv
        | Codec::XmssSha220256Pub
        | Codec::XmssSha220256Priv => Ok(Box::new(xmss::View::try_from(mk)?)),
        _ => Err(AttributesError::UnsupportedCodec(mk.codec).into()),
    }
}
/// Builds the cipher-attributes view for the viewed Multikey.
pub(crate) fn dispatch_cipher_attr_view<'a>(
    mk: &'a Multikey,
) -> Result<Box<dyn CipherAttrView + 'a>, Error> {
    let codec = if let Some(bytes) = mk.attributes.get(&AttrId::CipherCodec) {
        Codec::try_from(bytes.as_slice())?
    } else {
        mk.codec
    };
    match codec {
        Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(mk)?)),
        _ => Err(CipherError::UnsupportedCodec(codec).into()),
    }
}
/// Builds the key-data view for the viewed Multikey.
pub(crate) fn dispatch_data_view<'a>(mk: &'a Multikey) -> Result<Box<dyn DataView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1PrivShare
        | Codec::Bls12381G1Priv
        | Codec::Bls12381G1Pub
        | Codec::Bls12381G1PubShare
        | Codec::Bls12381G2PrivShare
        | Codec::Bls12381G2Priv
        | Codec::Bls12381G2Pub
        | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(mk)?)),
        Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(mk)?)),
        Codec::Secp256K1Pub | Codec::Secp256K1Priv => Ok(Box::new(secp256k1::View::try_from(mk)?)),
        Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(mk)?)),
        Codec::SlhDsaSha2128FPub
        | Codec::SlhDsaSha2128SPub
        | Codec::SlhDsaSha2192FPub
        | Codec::SlhDsaSha2192SPub
        | Codec::SlhDsaSha2256FPub
        | Codec::SlhDsaSha2256SPub
        | Codec::SlhDsaShake128FPub
        | Codec::SlhDsaShake128SPub
        | Codec::SlhDsaShake192FPub
        | Codec::SlhDsaShake192SPub
        | Codec::SlhDsaShake256FPub
        | Codec::SlhDsaShake256SPub
        | Codec::SlhDsaSha2128FPriv
        | Codec::SlhDsaSha2128SPriv
        | Codec::SlhDsaSha2192FPriv
        | Codec::SlhDsaSha2192SPriv
        | Codec::SlhDsaSha2256FPriv
        | Codec::SlhDsaSha2256SPriv
        | Codec::SlhDsaShake128FPriv
        | Codec::SlhDsaShake128SPriv
        | Codec::SlhDsaShake192FPriv
        | Codec::SlhDsaShake192SPriv
        | Codec::SlhDsaShake256FPriv
        | Codec::SlhDsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(mk)?)),
        Codec::MlDsa65Pub | Codec::MlDsa65Priv | Codec::MlDsa87Pub | Codec::MlDsa87Priv => {
            Ok(Box::new(ml_dsa::View::try_from(mk)?))
        }
        Codec::Mayo1Pub
        | Codec::Mayo1Priv
        | Codec::Mayo2Pub
        | Codec::Mayo2Priv
        | Codec::Mayo3Pub
        | Codec::Mayo3Priv
        | Codec::Mayo5Pub
        | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(mk)?)),
        Codec::FnDsa512Pub | Codec::FnDsa512Priv | Codec::FnDsa1024Pub | Codec::FnDsa1024Priv => {
            Ok(Box::new(fn_dsa::View::try_from(mk)?))
        }
        Codec::Mlkem768Pub | Codec::Mlkem768Priv | Codec::Mlkem1024Pub | Codec::Mlkem1024Priv => {
            Ok(Box::new(ml_kem::View::try_from(mk)?))
        }
        Codec::Sntrup761Pub
        | Codec::Sntrup761Priv
        | Codec::Sntrup857Pub
        | Codec::Sntrup857Priv
        | Codec::Sntrup953Pub
        | Codec::Sntrup953Priv
        | Codec::Sntrup1013Pub
        | Codec::Sntrup1013Priv
        | Codec::Sntrup1277Pub
        | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(mk)?)),
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
            Ok(Box::new(classic_mceliece::View::try_from(mk)?))
        }
        Codec::FrodoKem640AesPub
        | Codec::FrodoKem640AesPriv
        | Codec::FrodoKem976AesPub
        | Codec::FrodoKem976AesPriv
        | Codec::FrodoKem1344AesPub
        | Codec::FrodoKem1344AesPriv
        | Codec::FrodoKem640ShakePub
        | Codec::FrodoKem640ShakePriv
        | Codec::FrodoKem976ShakePub
        | Codec::FrodoKem976ShakePriv
        | Codec::FrodoKem1344ShakePub
        | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(mk)?)),
        Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(mk)?)),
        Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
            Ok(Box::new(x25519_sntrup761::View::try_from(mk)?))
        }
        Codec::X25519Frodokem640AesPub
        | Codec::X25519Frodokem640AesPriv
        | Codec::X25519Frodokem640ShakePub
        | Codec::X25519Frodokem640ShakePriv => {
            Ok(Box::new(x25519_frodokem640::View::try_from(mk)?))
        }
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
            Ok(Box::new(x25519_mceliece348864::View::try_from(mk)?))
        }
        Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
            Ok(Box::new(x25519_mlkem768::View::try_from(mk)?))
        }
        Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
            Ok(Box::new(ed25519_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
            Ok(Box::new(ed25519_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
            Ok(Box::new(bls12381_g1_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
            Ok(Box::new(bls12381_g1_fndsa512::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
            Ok(Box::new(bls12381_g1_mayo1::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
            Ok(Box::new(bls12381_g1_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
            Ok(Box::new(ed25519_fndsa512::View::try_from(mk)?))
        }
        Codec::P256Pub
        | Codec::P256Priv
        | Codec::P384Pub
        | Codec::P384Priv
        | Codec::P521Pub
        | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(mk)?)),
        Codec::Rsa2048Pub
        | Codec::Rsa2048Priv
        | Codec::Rsa3072Pub
        | Codec::Rsa3072Priv
        | Codec::Rsa4096Pub
        | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Pub
        | Codec::LamportSha3256Priv
        | Codec::LamportSha3256PrivShare
        | Codec::LamportSha3384Pub
        | Codec::LamportSha3384Priv
        | Codec::LamportSha3384PrivShare
        | Codec::LamportSha3512Pub
        | Codec::LamportSha3512Priv
        | Codec::LamportSha3512PrivShare
        | Codec::LamportSha2256Pub
        | Codec::LamportSha2256Priv
        | Codec::LamportSha2256PrivShare
        | Codec::LamportSha2384Pub
        | Codec::LamportSha2384Priv
        | Codec::LamportSha2384PrivShare
        | Codec::LamportSha2512Pub
        | Codec::LamportSha2512Priv
        | Codec::LamportSha2512PrivShare
        | Codec::LamportBlake2B512Pub
        | Codec::LamportBlake2B512Priv
        | Codec::LamportBlake2B512PrivShare
        | Codec::LamportBlake2S256Pub
        | Codec::LamportBlake2S256Priv
        | Codec::LamportBlake2S256PrivShare
        | Codec::LamportBlake3256Pub
        | Codec::LamportBlake3256Priv
        | Codec::LamportBlake3256PrivShare
        | Codec::LamportShake128Pub
        | Codec::LamportShake128Priv
        | Codec::LamportShake128PrivShare
        | Codec::LamportShake256Pub
        | Codec::LamportShake256Priv
        | Codec::LamportShake256PrivShare => Ok(Box::new(lamport::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3256Pub
        | Codec::LamportMerkleSha3256Priv
        | Codec::LamportMerkleSha3256PrivShare
        | Codec::LamportMerkleSha3384Pub
        | Codec::LamportMerkleSha3384Priv
        | Codec::LamportMerkleSha3384PrivShare
        | Codec::LamportMerkleSha3512Pub
        | Codec::LamportMerkleSha3512Priv
        | Codec::LamportMerkleSha3512PrivShare
        | Codec::LamportMerkleSha2256Pub
        | Codec::LamportMerkleSha2256Priv
        | Codec::LamportMerkleSha2256PrivShare
        | Codec::LamportMerkleSha2384Pub
        | Codec::LamportMerkleSha2384Priv
        | Codec::LamportMerkleSha2384PrivShare
        | Codec::LamportMerkleSha2512Pub
        | Codec::LamportMerkleSha2512Priv
        | Codec::LamportMerkleSha2512PrivShare
        | Codec::LamportMerkleBlake2B512Pub
        | Codec::LamportMerkleBlake2B512Priv
        | Codec::LamportMerkleBlake2B512PrivShare
        | Codec::LamportMerkleBlake2S256Pub
        | Codec::LamportMerkleBlake2S256Priv
        | Codec::LamportMerkleBlake2S256PrivShare
        | Codec::LamportMerkleBlake3256Pub
        | Codec::LamportMerkleBlake3256Priv
        | Codec::LamportMerkleBlake3256PrivShare
        | Codec::LamportMerkleShake128Pub
        | Codec::LamportMerkleShake128Priv
        | Codec::LamportMerkleShake128PrivShare
        | Codec::LamportMerkleShake256Pub
        | Codec::LamportMerkleShake256Priv
        | Codec::LamportMerkleShake256PrivShare => {
            Ok(Box::new(lamport_merkle::View::try_from(mk)?))
        }
        #[cfg(feature = "xmss")]
        Codec::XmssSha210256Pub
        | Codec::XmssSha210256Priv
        | Codec::XmssSha216256Pub
        | Codec::XmssSha216256Priv
        | Codec::XmssSha220256Pub
        | Codec::XmssSha220256Priv => Ok(Box::new(xmss::View::try_from(mk)?)),
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
}
/// Builds the kdf-attributes view for the viewed Multikey.
pub(crate) fn dispatch_kdf_attr_view<'a>(
    mk: &'a Multikey,
) -> Result<Box<dyn KdfAttrView + 'a>, Error> {
    let codec = if let Some(bytes) = mk.attributes.get(&AttrId::KdfCodec) {
        Codec::try_from(bytes.as_slice())?
    } else {
        mk.codec
    };
    match codec {
        Codec::BcryptPbkdf => Ok(Box::new(bcrypt::View::try_from(mk)?)),
        _ => Err(KdfError::UnsupportedCodec(codec).into()),
    }
}
/// Builds the threshold-attributes view for the viewed Multikey.
pub(crate) fn dispatch_threshold_attr_view<'a>(
    mk: &'a Multikey,
) -> Result<Box<dyn ThresholdAttrView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1PrivShare
        | Codec::Bls12381G1Priv
        | Codec::Bls12381G1Pub
        | Codec::Bls12381G1PubShare
        | Codec::Bls12381G2PrivShare
        | Codec::Bls12381G2Priv
        | Codec::Bls12381G2Pub
        | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(mk)?)),
        Codec::Ed25519ThreshPrivShare
        | Codec::P256ThreshPrivShare
        | Codec::P384ThreshPrivShare
        | Codec::Secp256K1ThreshPrivShare
        | Codec::Bls12381ThreshPrivShare
        | Codec::Ed448ThreshPrivShare => {
            Ok(Box::new(crate::views::dkg_threshold::View::try_from(mk)?))
        }
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
}
/// Builds the threshold-key metadata view for the viewed Multikey.
pub(crate) fn dispatch_threshold_key_view<'a>(
    mk: &'a Multikey,
) -> Result<Box<dyn ThresholdKeyView + 'a>, Error> {
    match mk.codec {
        Codec::Ed25519ThreshPrivShare
        | Codec::P256ThreshPrivShare
        | Codec::P384ThreshPrivShare
        | Codec::Secp256K1ThreshPrivShare
        | Codec::Bls12381ThreshPrivShare
        | Codec::Ed448ThreshPrivShare => {
            Ok(Box::new(crate::views::dkg_threshold::View::try_from(mk)?))
        }
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
}
/// Builds the cipher view for the viewed Multikey using the cipher key.
pub(crate) fn dispatch_cipher_view<'a>(
    mk: &'a Multikey,
    cipher: &'a Multikey,
) -> Result<Box<dyn CipherView + 'a>, Error> {
    match cipher.codec {
        Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::new(mk, cipher))),
        _ => Err(CipherError::UnsupportedCodec(cipher.codec).into()),
    }
}
/// Builds the key-conversion view for the viewed Multikey.
pub(crate) fn dispatch_conv_view<'a>(mk: &'a Multikey) -> Result<Box<dyn ConvView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1PrivShare
        | Codec::Bls12381G1Priv
        | Codec::Bls12381G1Pub
        | Codec::Bls12381G1PubShare
        | Codec::Bls12381G2PrivShare
        | Codec::Bls12381G2Priv
        | Codec::Bls12381G2Pub
        | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(mk)?)),
        Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(mk)?)),
        Codec::Secp256K1Pub | Codec::Secp256K1Priv => Ok(Box::new(secp256k1::View::try_from(mk)?)),
        Codec::SlhDsaSha2128FPub
        | Codec::SlhDsaSha2128SPub
        | Codec::SlhDsaSha2192FPub
        | Codec::SlhDsaSha2192SPub
        | Codec::SlhDsaSha2256FPub
        | Codec::SlhDsaSha2256SPub
        | Codec::SlhDsaShake128FPub
        | Codec::SlhDsaShake128SPub
        | Codec::SlhDsaShake192FPub
        | Codec::SlhDsaShake192SPub
        | Codec::SlhDsaShake256FPub
        | Codec::SlhDsaShake256SPub
        | Codec::SlhDsaSha2128FPriv
        | Codec::SlhDsaSha2128SPriv
        | Codec::SlhDsaSha2192FPriv
        | Codec::SlhDsaSha2192SPriv
        | Codec::SlhDsaSha2256FPriv
        | Codec::SlhDsaSha2256SPriv
        | Codec::SlhDsaShake128FPriv
        | Codec::SlhDsaShake128SPriv
        | Codec::SlhDsaShake192FPriv
        | Codec::SlhDsaShake192SPriv
        | Codec::SlhDsaShake256FPriv
        | Codec::SlhDsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(mk)?)),
        Codec::MlDsa65Pub | Codec::MlDsa65Priv | Codec::MlDsa87Pub | Codec::MlDsa87Priv => {
            Ok(Box::new(ml_dsa::View::try_from(mk)?))
        }
        Codec::Mayo1Pub
        | Codec::Mayo1Priv
        | Codec::Mayo2Pub
        | Codec::Mayo2Priv
        | Codec::Mayo3Pub
        | Codec::Mayo3Priv
        | Codec::Mayo5Pub
        | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(mk)?)),
        Codec::FnDsa512Pub | Codec::FnDsa512Priv | Codec::FnDsa1024Pub | Codec::FnDsa1024Priv => {
            Ok(Box::new(fn_dsa::View::try_from(mk)?))
        }
        Codec::Mlkem768Pub | Codec::Mlkem768Priv | Codec::Mlkem1024Pub | Codec::Mlkem1024Priv => {
            Ok(Box::new(ml_kem::View::try_from(mk)?))
        }
        Codec::Sntrup761Pub
        | Codec::Sntrup761Priv
        | Codec::Sntrup857Pub
        | Codec::Sntrup857Priv
        | Codec::Sntrup953Pub
        | Codec::Sntrup953Priv
        | Codec::Sntrup1013Pub
        | Codec::Sntrup1013Priv
        | Codec::Sntrup1277Pub
        | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(mk)?)),
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
            Ok(Box::new(classic_mceliece::View::try_from(mk)?))
        }
        Codec::FrodoKem640AesPub
        | Codec::FrodoKem640AesPriv
        | Codec::FrodoKem976AesPub
        | Codec::FrodoKem976AesPriv
        | Codec::FrodoKem1344AesPub
        | Codec::FrodoKem1344AesPriv
        | Codec::FrodoKem640ShakePub
        | Codec::FrodoKem640ShakePriv
        | Codec::FrodoKem976ShakePub
        | Codec::FrodoKem976ShakePriv
        | Codec::FrodoKem1344ShakePub
        | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(mk)?)),
        Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(mk)?)),
        Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
            Ok(Box::new(x25519_sntrup761::View::try_from(mk)?))
        }
        Codec::X25519Frodokem640AesPub
        | Codec::X25519Frodokem640AesPriv
        | Codec::X25519Frodokem640ShakePub
        | Codec::X25519Frodokem640ShakePriv => {
            Ok(Box::new(x25519_frodokem640::View::try_from(mk)?))
        }
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
            Ok(Box::new(x25519_mceliece348864::View::try_from(mk)?))
        }
        Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
            Ok(Box::new(x25519_mlkem768::View::try_from(mk)?))
        }
        Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
            Ok(Box::new(ed25519_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
            Ok(Box::new(ed25519_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
            Ok(Box::new(bls12381_g1_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
            Ok(Box::new(bls12381_g1_fndsa512::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
            Ok(Box::new(bls12381_g1_mayo1::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
            Ok(Box::new(bls12381_g1_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
            Ok(Box::new(ed25519_fndsa512::View::try_from(mk)?))
        }
        Codec::P256Pub
        | Codec::P256Priv
        | Codec::P384Pub
        | Codec::P384Priv
        | Codec::P521Pub
        | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(mk)?)),
        Codec::Rsa2048Pub
        | Codec::Rsa2048Priv
        | Codec::Rsa3072Pub
        | Codec::Rsa3072Priv
        | Codec::Rsa4096Pub
        | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Pub
        | Codec::LamportSha3256Priv
        | Codec::LamportSha3256PrivShare
        | Codec::LamportSha3384Pub
        | Codec::LamportSha3384Priv
        | Codec::LamportSha3384PrivShare
        | Codec::LamportSha3512Pub
        | Codec::LamportSha3512Priv
        | Codec::LamportSha3512PrivShare
        | Codec::LamportSha2256Pub
        | Codec::LamportSha2256Priv
        | Codec::LamportSha2256PrivShare
        | Codec::LamportSha2384Pub
        | Codec::LamportSha2384Priv
        | Codec::LamportSha2384PrivShare
        | Codec::LamportSha2512Pub
        | Codec::LamportSha2512Priv
        | Codec::LamportSha2512PrivShare
        | Codec::LamportBlake2B512Pub
        | Codec::LamportBlake2B512Priv
        | Codec::LamportBlake2B512PrivShare
        | Codec::LamportBlake2S256Pub
        | Codec::LamportBlake2S256Priv
        | Codec::LamportBlake2S256PrivShare
        | Codec::LamportBlake3256Pub
        | Codec::LamportBlake3256Priv
        | Codec::LamportBlake3256PrivShare
        | Codec::LamportShake128Pub
        | Codec::LamportShake128Priv
        | Codec::LamportShake128PrivShare
        | Codec::LamportShake256Pub
        | Codec::LamportShake256Priv
        | Codec::LamportShake256PrivShare => Ok(Box::new(lamport::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3256Pub
        | Codec::LamportMerkleSha3256Priv
        | Codec::LamportMerkleSha3256PrivShare
        | Codec::LamportMerkleSha3384Pub
        | Codec::LamportMerkleSha3384Priv
        | Codec::LamportMerkleSha3384PrivShare
        | Codec::LamportMerkleSha3512Pub
        | Codec::LamportMerkleSha3512Priv
        | Codec::LamportMerkleSha3512PrivShare
        | Codec::LamportMerkleSha2256Pub
        | Codec::LamportMerkleSha2256Priv
        | Codec::LamportMerkleSha2256PrivShare
        | Codec::LamportMerkleSha2384Pub
        | Codec::LamportMerkleSha2384Priv
        | Codec::LamportMerkleSha2384PrivShare
        | Codec::LamportMerkleSha2512Pub
        | Codec::LamportMerkleSha2512Priv
        | Codec::LamportMerkleSha2512PrivShare
        | Codec::LamportMerkleBlake2B512Pub
        | Codec::LamportMerkleBlake2B512Priv
        | Codec::LamportMerkleBlake2B512PrivShare
        | Codec::LamportMerkleBlake2S256Pub
        | Codec::LamportMerkleBlake2S256Priv
        | Codec::LamportMerkleBlake2S256PrivShare
        | Codec::LamportMerkleBlake3256Pub
        | Codec::LamportMerkleBlake3256Priv
        | Codec::LamportMerkleBlake3256PrivShare
        | Codec::LamportMerkleShake128Pub
        | Codec::LamportMerkleShake128Priv
        | Codec::LamportMerkleShake128PrivShare
        | Codec::LamportMerkleShake256Pub
        | Codec::LamportMerkleShake256Priv
        | Codec::LamportMerkleShake256PrivShare => {
            Ok(Box::new(lamport_merkle::View::try_from(mk)?))
        }
        #[cfg(feature = "xmss")]
        Codec::XmssSha210256Pub
        | Codec::XmssSha210256Priv
        | Codec::XmssSha216256Pub
        | Codec::XmssSha216256Priv
        | Codec::XmssSha220256Pub
        | Codec::XmssSha220256Priv => Ok(Box::new(xmss::View::try_from(mk)?)),
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
}
/// Builds the fingerprint view for the viewed Multikey.
pub(crate) fn dispatch_fingerprint_view<'a>(
    mk: &'a Multikey,
) -> Result<Box<dyn FingerprintView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1PrivShare
        | Codec::Bls12381G1Priv
        | Codec::Bls12381G1Pub
        | Codec::Bls12381G1PubShare
        | Codec::Bls12381G2PrivShare
        | Codec::Bls12381G2Priv
        | Codec::Bls12381G2Pub
        | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(mk)?)),
        Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(mk)?)),
        Codec::Secp256K1Pub | Codec::Secp256K1Priv => Ok(Box::new(secp256k1::View::try_from(mk)?)),
        Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(mk)?)),
        Codec::SlhDsaSha2128FPub
        | Codec::SlhDsaSha2128SPub
        | Codec::SlhDsaSha2192FPub
        | Codec::SlhDsaSha2192SPub
        | Codec::SlhDsaSha2256FPub
        | Codec::SlhDsaSha2256SPub
        | Codec::SlhDsaShake128FPub
        | Codec::SlhDsaShake128SPub
        | Codec::SlhDsaShake192FPub
        | Codec::SlhDsaShake192SPub
        | Codec::SlhDsaShake256FPub
        | Codec::SlhDsaShake256SPub
        | Codec::SlhDsaSha2128FPriv
        | Codec::SlhDsaSha2128SPriv
        | Codec::SlhDsaSha2192FPriv
        | Codec::SlhDsaSha2192SPriv
        | Codec::SlhDsaSha2256FPriv
        | Codec::SlhDsaSha2256SPriv
        | Codec::SlhDsaShake128FPriv
        | Codec::SlhDsaShake128SPriv
        | Codec::SlhDsaShake192FPriv
        | Codec::SlhDsaShake192SPriv
        | Codec::SlhDsaShake256FPriv
        | Codec::SlhDsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(mk)?)),
        Codec::MlDsa65Pub | Codec::MlDsa65Priv | Codec::MlDsa87Pub | Codec::MlDsa87Priv => {
            Ok(Box::new(ml_dsa::View::try_from(mk)?))
        }
        Codec::Mayo1Pub
        | Codec::Mayo1Priv
        | Codec::Mayo2Pub
        | Codec::Mayo2Priv
        | Codec::Mayo3Pub
        | Codec::Mayo3Priv
        | Codec::Mayo5Pub
        | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(mk)?)),
        Codec::FnDsa512Pub | Codec::FnDsa512Priv | Codec::FnDsa1024Pub | Codec::FnDsa1024Priv => {
            Ok(Box::new(fn_dsa::View::try_from(mk)?))
        }
        Codec::Mlkem768Pub | Codec::Mlkem768Priv | Codec::Mlkem1024Pub | Codec::Mlkem1024Priv => {
            Ok(Box::new(ml_kem::View::try_from(mk)?))
        }
        Codec::Sntrup761Pub
        | Codec::Sntrup761Priv
        | Codec::Sntrup857Pub
        | Codec::Sntrup857Priv
        | Codec::Sntrup953Pub
        | Codec::Sntrup953Priv
        | Codec::Sntrup1013Pub
        | Codec::Sntrup1013Priv
        | Codec::Sntrup1277Pub
        | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(mk)?)),
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
            Ok(Box::new(classic_mceliece::View::try_from(mk)?))
        }
        Codec::FrodoKem640AesPub
        | Codec::FrodoKem640AesPriv
        | Codec::FrodoKem976AesPub
        | Codec::FrodoKem976AesPriv
        | Codec::FrodoKem1344AesPub
        | Codec::FrodoKem1344AesPriv
        | Codec::FrodoKem640ShakePub
        | Codec::FrodoKem640ShakePriv
        | Codec::FrodoKem976ShakePub
        | Codec::FrodoKem976ShakePriv
        | Codec::FrodoKem1344ShakePub
        | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(mk)?)),
        Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(mk)?)),
        Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
            Ok(Box::new(x25519_sntrup761::View::try_from(mk)?))
        }
        Codec::X25519Frodokem640AesPub
        | Codec::X25519Frodokem640AesPriv
        | Codec::X25519Frodokem640ShakePub
        | Codec::X25519Frodokem640ShakePriv => {
            Ok(Box::new(x25519_frodokem640::View::try_from(mk)?))
        }
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
            Ok(Box::new(x25519_mceliece348864::View::try_from(mk)?))
        }
        Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
            Ok(Box::new(x25519_mlkem768::View::try_from(mk)?))
        }
        Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
            Ok(Box::new(ed25519_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
            Ok(Box::new(ed25519_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
            Ok(Box::new(bls12381_g1_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
            Ok(Box::new(bls12381_g1_fndsa512::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
            Ok(Box::new(bls12381_g1_mayo1::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
            Ok(Box::new(bls12381_g1_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
            Ok(Box::new(ed25519_fndsa512::View::try_from(mk)?))
        }
        Codec::P256Pub
        | Codec::P256Priv
        | Codec::P384Pub
        | Codec::P384Priv
        | Codec::P521Pub
        | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(mk)?)),
        Codec::Rsa2048Pub
        | Codec::Rsa2048Priv
        | Codec::Rsa3072Pub
        | Codec::Rsa3072Priv
        | Codec::Rsa4096Pub
        | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Pub
        | Codec::LamportSha3256Priv
        | Codec::LamportSha3256PrivShare
        | Codec::LamportSha3384Pub
        | Codec::LamportSha3384Priv
        | Codec::LamportSha3384PrivShare
        | Codec::LamportSha3512Pub
        | Codec::LamportSha3512Priv
        | Codec::LamportSha3512PrivShare
        | Codec::LamportSha2256Pub
        | Codec::LamportSha2256Priv
        | Codec::LamportSha2256PrivShare
        | Codec::LamportSha2384Pub
        | Codec::LamportSha2384Priv
        | Codec::LamportSha2384PrivShare
        | Codec::LamportSha2512Pub
        | Codec::LamportSha2512Priv
        | Codec::LamportSha2512PrivShare
        | Codec::LamportBlake2B512Pub
        | Codec::LamportBlake2B512Priv
        | Codec::LamportBlake2B512PrivShare
        | Codec::LamportBlake2S256Pub
        | Codec::LamportBlake2S256Priv
        | Codec::LamportBlake2S256PrivShare
        | Codec::LamportBlake3256Pub
        | Codec::LamportBlake3256Priv
        | Codec::LamportBlake3256PrivShare
        | Codec::LamportShake128Pub
        | Codec::LamportShake128Priv
        | Codec::LamportShake128PrivShare
        | Codec::LamportShake256Pub
        | Codec::LamportShake256Priv
        | Codec::LamportShake256PrivShare => Ok(Box::new(lamport::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3256Pub
        | Codec::LamportMerkleSha3256Priv
        | Codec::LamportMerkleSha3256PrivShare
        | Codec::LamportMerkleSha3384Pub
        | Codec::LamportMerkleSha3384Priv
        | Codec::LamportMerkleSha3384PrivShare
        | Codec::LamportMerkleSha3512Pub
        | Codec::LamportMerkleSha3512Priv
        | Codec::LamportMerkleSha3512PrivShare
        | Codec::LamportMerkleSha2256Pub
        | Codec::LamportMerkleSha2256Priv
        | Codec::LamportMerkleSha2256PrivShare
        | Codec::LamportMerkleSha2384Pub
        | Codec::LamportMerkleSha2384Priv
        | Codec::LamportMerkleSha2384PrivShare
        | Codec::LamportMerkleSha2512Pub
        | Codec::LamportMerkleSha2512Priv
        | Codec::LamportMerkleSha2512PrivShare
        | Codec::LamportMerkleBlake2B512Pub
        | Codec::LamportMerkleBlake2B512Priv
        | Codec::LamportMerkleBlake2B512PrivShare
        | Codec::LamportMerkleBlake2S256Pub
        | Codec::LamportMerkleBlake2S256Priv
        | Codec::LamportMerkleBlake2S256PrivShare
        | Codec::LamportMerkleBlake3256Pub
        | Codec::LamportMerkleBlake3256Priv
        | Codec::LamportMerkleBlake3256PrivShare
        | Codec::LamportMerkleShake128Pub
        | Codec::LamportMerkleShake128Priv
        | Codec::LamportMerkleShake128PrivShare
        | Codec::LamportMerkleShake256Pub
        | Codec::LamportMerkleShake256Priv
        | Codec::LamportMerkleShake256PrivShare => {
            Ok(Box::new(lamport_merkle::View::try_from(mk)?))
        }
        #[cfg(feature = "xmss")]
        Codec::XmssSha210256Pub
        | Codec::XmssSha210256Priv
        | Codec::XmssSha216256Pub
        | Codec::XmssSha216256Priv
        | Codec::XmssSha220256Pub
        | Codec::XmssSha220256Priv => Ok(Box::new(xmss::View::try_from(mk)?)),
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
}
/// Builds the kdf view for the viewed Multikey using the kdf key.
pub(crate) fn dispatch_kdf_view<'a>(
    mk: &'a Multikey,
    kdf: &'a Multikey,
) -> Result<Box<dyn KdfView + 'a>, Error> {
    match kdf.codec {
        Codec::BcryptPbkdf => Ok(Box::new(bcrypt::View::new(mk, kdf))),
        _ => Err(KdfError::UnsupportedCodec(kdf.codec).into()),
    }
}
/// Builds the seal view for the viewed Multikey.
pub(crate) fn dispatch_seal_view<'a>(mk: &'a Multikey) -> Result<Box<dyn SealView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1Pub
        | Codec::Bls12381G1Priv
        | Codec::Bls12381G2Pub
        | Codec::Bls12381G2Priv => Ok(Box::new(bls12381::View::try_from(mk)?)),
        Codec::Mlkem768Pub | Codec::Mlkem768Priv | Codec::Mlkem1024Pub | Codec::Mlkem1024Priv => {
            Ok(Box::new(ml_kem::View::try_from(mk)?))
        }
        Codec::Sntrup761Pub
        | Codec::Sntrup761Priv
        | Codec::Sntrup857Pub
        | Codec::Sntrup857Priv
        | Codec::Sntrup953Pub
        | Codec::Sntrup953Priv
        | Codec::Sntrup1013Pub
        | Codec::Sntrup1013Priv
        | Codec::Sntrup1277Pub
        | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(mk)?)),
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
            Ok(Box::new(classic_mceliece::View::try_from(mk)?))
        }
        Codec::FrodoKem640AesPub
        | Codec::FrodoKem640AesPriv
        | Codec::FrodoKem976AesPub
        | Codec::FrodoKem976AesPriv
        | Codec::FrodoKem1344AesPub
        | Codec::FrodoKem1344AesPriv
        | Codec::FrodoKem640ShakePub
        | Codec::FrodoKem640ShakePriv
        | Codec::FrodoKem976ShakePub
        | Codec::FrodoKem976ShakePriv
        | Codec::FrodoKem1344ShakePub
        | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(mk)?)),
        Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(mk)?)),
        Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
            Ok(Box::new(x25519_sntrup761::View::try_from(mk)?))
        }
        Codec::X25519Frodokem640AesPub
        | Codec::X25519Frodokem640AesPriv
        | Codec::X25519Frodokem640ShakePub
        | Codec::X25519Frodokem640ShakePriv => {
            Ok(Box::new(x25519_frodokem640::View::try_from(mk)?))
        }
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
            Ok(Box::new(x25519_mceliece348864::View::try_from(mk)?))
        }
        Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
            Ok(Box::new(x25519_mlkem768::View::try_from(mk)?))
        }
        Codec::Rsa2048Pub
        | Codec::Rsa2048Priv
        | Codec::Rsa3072Pub
        | Codec::Rsa3072Priv
        | Codec::Rsa4096Pub
        | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(mk)?)),
        Codec::P256Pub
        | Codec::P256Priv
        | Codec::P384Pub
        | Codec::P384Priv
        | Codec::P521Pub
        | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(mk)?)),
        Codec::Secp256K1Pub | Codec::Secp256K1Priv => Ok(Box::new(secp256k1::View::try_from(mk)?)),
        _ => Err(SealError::NotEncryptionKey.into()),
    }
}
/// Builds the open view for the viewed Multikey.
pub(crate) fn dispatch_open_view<'a>(mk: &'a Multikey) -> Result<Box<dyn OpenView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1Pub
        | Codec::Bls12381G1Priv
        | Codec::Bls12381G2Pub
        | Codec::Bls12381G2Priv => Ok(Box::new(bls12381::View::try_from(mk)?)),
        Codec::Mlkem768Pub | Codec::Mlkem768Priv | Codec::Mlkem1024Pub | Codec::Mlkem1024Priv => {
            Ok(Box::new(ml_kem::View::try_from(mk)?))
        }
        Codec::Sntrup761Pub
        | Codec::Sntrup761Priv
        | Codec::Sntrup857Pub
        | Codec::Sntrup857Priv
        | Codec::Sntrup953Pub
        | Codec::Sntrup953Priv
        | Codec::Sntrup1013Pub
        | Codec::Sntrup1013Priv
        | Codec::Sntrup1277Pub
        | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(mk)?)),
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
            Ok(Box::new(classic_mceliece::View::try_from(mk)?))
        }
        Codec::FrodoKem640AesPub
        | Codec::FrodoKem640AesPriv
        | Codec::FrodoKem976AesPub
        | Codec::FrodoKem976AesPriv
        | Codec::FrodoKem1344AesPub
        | Codec::FrodoKem1344AesPriv
        | Codec::FrodoKem640ShakePub
        | Codec::FrodoKem640ShakePriv
        | Codec::FrodoKem976ShakePub
        | Codec::FrodoKem976ShakePriv
        | Codec::FrodoKem1344ShakePub
        | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(mk)?)),
        Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(mk)?)),
        Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
            Ok(Box::new(x25519_sntrup761::View::try_from(mk)?))
        }
        Codec::X25519Frodokem640AesPub
        | Codec::X25519Frodokem640AesPriv
        | Codec::X25519Frodokem640ShakePub
        | Codec::X25519Frodokem640ShakePriv => {
            Ok(Box::new(x25519_frodokem640::View::try_from(mk)?))
        }
        #[cfg(feature = "deprecated")]
        #[allow(deprecated)]
        Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
            Ok(Box::new(x25519_mceliece348864::View::try_from(mk)?))
        }
        Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
            Ok(Box::new(x25519_mlkem768::View::try_from(mk)?))
        }
        Codec::Rsa2048Pub
        | Codec::Rsa2048Priv
        | Codec::Rsa3072Pub
        | Codec::Rsa3072Priv
        | Codec::Rsa4096Pub
        | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(mk)?)),
        Codec::P256Pub
        | Codec::P256Priv
        | Codec::P384Pub
        | Codec::P384Priv
        | Codec::P521Pub
        | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(mk)?)),
        Codec::Secp256K1Pub | Codec::Secp256K1Priv => Ok(Box::new(secp256k1::View::try_from(mk)?)),
        _ => Err(SealError::NotEncryptionKey.into()),
    }
}
/// Builds the signature view for the viewed Multikey.
pub(crate) fn dispatch_sign_view<'a>(mk: &'a Multikey) -> Result<Box<dyn SignView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1PrivShare
        | Codec::Bls12381G1Priv
        | Codec::Bls12381G1Pub
        | Codec::Bls12381G1PubShare
        | Codec::Bls12381G2PrivShare
        | Codec::Bls12381G2Priv
        | Codec::Bls12381G2Pub
        | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(mk)?)),
        Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(mk)?)),
        Codec::Secp256K1Pub | Codec::Secp256K1Priv => Ok(Box::new(secp256k1::View::try_from(mk)?)),
        Codec::SlhDsaSha2128FPub
        | Codec::SlhDsaSha2128SPub
        | Codec::SlhDsaSha2192FPub
        | Codec::SlhDsaSha2192SPub
        | Codec::SlhDsaSha2256FPub
        | Codec::SlhDsaSha2256SPub
        | Codec::SlhDsaShake128FPub
        | Codec::SlhDsaShake128SPub
        | Codec::SlhDsaShake192FPub
        | Codec::SlhDsaShake192SPub
        | Codec::SlhDsaShake256FPub
        | Codec::SlhDsaShake256SPub
        | Codec::SlhDsaSha2128FPriv
        | Codec::SlhDsaSha2128SPriv
        | Codec::SlhDsaSha2192FPriv
        | Codec::SlhDsaSha2192SPriv
        | Codec::SlhDsaSha2256FPriv
        | Codec::SlhDsaSha2256SPriv
        | Codec::SlhDsaShake128FPriv
        | Codec::SlhDsaShake128SPriv
        | Codec::SlhDsaShake192FPriv
        | Codec::SlhDsaShake192SPriv
        | Codec::SlhDsaShake256FPriv
        | Codec::SlhDsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(mk)?)),
        Codec::MlDsa65Pub | Codec::MlDsa65Priv | Codec::MlDsa87Pub | Codec::MlDsa87Priv => {
            Ok(Box::new(ml_dsa::View::try_from(mk)?))
        }
        Codec::Mayo1Pub
        | Codec::Mayo1Priv
        | Codec::Mayo2Pub
        | Codec::Mayo2Priv
        | Codec::Mayo3Pub
        | Codec::Mayo3Priv
        | Codec::Mayo5Pub
        | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(mk)?)),
        Codec::FnDsa512Pub | Codec::FnDsa512Priv | Codec::FnDsa1024Pub | Codec::FnDsa1024Priv => {
            Ok(Box::new(fn_dsa::View::try_from(mk)?))
        }
        Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
            Ok(Box::new(ed25519_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
            Ok(Box::new(ed25519_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
            Ok(Box::new(bls12381_g1_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
            Ok(Box::new(bls12381_g1_fndsa512::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
            Ok(Box::new(bls12381_g1_mayo1::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
            Ok(Box::new(bls12381_g1_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
            Ok(Box::new(ed25519_fndsa512::View::try_from(mk)?))
        }
        Codec::P256Pub
        | Codec::P256Priv
        | Codec::P384Pub
        | Codec::P384Priv
        | Codec::P521Pub
        | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(mk)?)),
        Codec::Rsa2048Pub
        | Codec::Rsa2048Priv
        | Codec::Rsa3072Pub
        | Codec::Rsa3072Priv
        | Codec::Rsa4096Pub
        | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Pub
        | Codec::LamportSha3256Priv
        | Codec::LamportSha3256PrivShare
        | Codec::LamportSha3384Pub
        | Codec::LamportSha3384Priv
        | Codec::LamportSha3384PrivShare
        | Codec::LamportSha3512Pub
        | Codec::LamportSha3512Priv
        | Codec::LamportSha3512PrivShare
        | Codec::LamportSha2256Pub
        | Codec::LamportSha2256Priv
        | Codec::LamportSha2256PrivShare
        | Codec::LamportSha2384Pub
        | Codec::LamportSha2384Priv
        | Codec::LamportSha2384PrivShare
        | Codec::LamportSha2512Pub
        | Codec::LamportSha2512Priv
        | Codec::LamportSha2512PrivShare
        | Codec::LamportBlake2B512Pub
        | Codec::LamportBlake2B512Priv
        | Codec::LamportBlake2B512PrivShare
        | Codec::LamportBlake2S256Pub
        | Codec::LamportBlake2S256Priv
        | Codec::LamportBlake2S256PrivShare
        | Codec::LamportBlake3256Pub
        | Codec::LamportBlake3256Priv
        | Codec::LamportBlake3256PrivShare
        | Codec::LamportShake128Pub
        | Codec::LamportShake128Priv
        | Codec::LamportShake128PrivShare
        | Codec::LamportShake256Pub
        | Codec::LamportShake256Priv
        | Codec::LamportShake256PrivShare => Ok(Box::new(lamport::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3256Pub
        | Codec::LamportMerkleSha3256Priv
        | Codec::LamportMerkleSha3256PrivShare
        | Codec::LamportMerkleSha3384Pub
        | Codec::LamportMerkleSha3384Priv
        | Codec::LamportMerkleSha3384PrivShare
        | Codec::LamportMerkleSha3512Pub
        | Codec::LamportMerkleSha3512Priv
        | Codec::LamportMerkleSha3512PrivShare
        | Codec::LamportMerkleSha2256Pub
        | Codec::LamportMerkleSha2256Priv
        | Codec::LamportMerkleSha2256PrivShare
        | Codec::LamportMerkleSha2384Pub
        | Codec::LamportMerkleSha2384Priv
        | Codec::LamportMerkleSha2384PrivShare
        | Codec::LamportMerkleSha2512Pub
        | Codec::LamportMerkleSha2512Priv
        | Codec::LamportMerkleSha2512PrivShare
        | Codec::LamportMerkleBlake2B512Pub
        | Codec::LamportMerkleBlake2B512Priv
        | Codec::LamportMerkleBlake2B512PrivShare
        | Codec::LamportMerkleBlake2S256Pub
        | Codec::LamportMerkleBlake2S256Priv
        | Codec::LamportMerkleBlake2S256PrivShare
        | Codec::LamportMerkleBlake3256Pub
        | Codec::LamportMerkleBlake3256Priv
        | Codec::LamportMerkleBlake3256PrivShare
        | Codec::LamportMerkleShake128Pub
        | Codec::LamportMerkleShake128Priv
        | Codec::LamportMerkleShake128PrivShare
        | Codec::LamportMerkleShake256Pub
        | Codec::LamportMerkleShake256Priv
        | Codec::LamportMerkleShake256PrivShare => {
            Ok(Box::new(lamport_merkle::View::try_from(mk)?))
        }
        #[cfg(feature = "xmss")]
        Codec::XmssSha210256Pub
        | Codec::XmssSha210256Priv
        | Codec::XmssSha216256Pub
        | Codec::XmssSha216256Priv
        | Codec::XmssSha220256Pub
        | Codec::XmssSha220256Priv => Ok(Box::new(xmss::View::try_from(mk)?)),
        Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(xeddsa::View::try_from(mk)?)),
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
}
/// Builds the threshold view for the viewed Multikey.
pub(crate) fn dispatch_threshold_view<'a>(
    mk: &'a Multikey,
) -> Result<Box<dyn ThresholdView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1Priv | Codec::Bls12381G2Priv => {
            Ok(Box::new(bls12381::View::try_from(mk)?))
        }
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Pub
        | Codec::LamportSha3256Priv
        | Codec::LamportSha3256PrivShare
        | Codec::LamportSha3384Pub
        | Codec::LamportSha3384Priv
        | Codec::LamportSha3384PrivShare
        | Codec::LamportSha3512Pub
        | Codec::LamportSha3512Priv
        | Codec::LamportSha3512PrivShare
        | Codec::LamportSha2256Pub
        | Codec::LamportSha2256Priv
        | Codec::LamportSha2256PrivShare
        | Codec::LamportSha2384Pub
        | Codec::LamportSha2384Priv
        | Codec::LamportSha2384PrivShare
        | Codec::LamportSha2512Pub
        | Codec::LamportSha2512Priv
        | Codec::LamportSha2512PrivShare
        | Codec::LamportBlake2B512Pub
        | Codec::LamportBlake2B512Priv
        | Codec::LamportBlake2B512PrivShare
        | Codec::LamportBlake2S256Pub
        | Codec::LamportBlake2S256Priv
        | Codec::LamportBlake2S256PrivShare
        | Codec::LamportBlake3256Pub
        | Codec::LamportBlake3256Priv
        | Codec::LamportBlake3256PrivShare
        | Codec::LamportShake128Pub
        | Codec::LamportShake128Priv
        | Codec::LamportShake128PrivShare
        | Codec::LamportShake256Pub
        | Codec::LamportShake256Priv
        | Codec::LamportShake256PrivShare => Ok(Box::new(lamport::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3256Pub
        | Codec::LamportMerkleSha3256Priv
        | Codec::LamportMerkleSha3256PrivShare
        | Codec::LamportMerkleSha3384Pub
        | Codec::LamportMerkleSha3384Priv
        | Codec::LamportMerkleSha3384PrivShare
        | Codec::LamportMerkleSha3512Pub
        | Codec::LamportMerkleSha3512Priv
        | Codec::LamportMerkleSha3512PrivShare
        | Codec::LamportMerkleSha2256Pub
        | Codec::LamportMerkleSha2256Priv
        | Codec::LamportMerkleSha2256PrivShare
        | Codec::LamportMerkleSha2384Pub
        | Codec::LamportMerkleSha2384Priv
        | Codec::LamportMerkleSha2384PrivShare
        | Codec::LamportMerkleSha2512Pub
        | Codec::LamportMerkleSha2512Priv
        | Codec::LamportMerkleSha2512PrivShare
        | Codec::LamportMerkleBlake2B512Pub
        | Codec::LamportMerkleBlake2B512Priv
        | Codec::LamportMerkleBlake2B512PrivShare
        | Codec::LamportMerkleBlake2S256Pub
        | Codec::LamportMerkleBlake2S256Priv
        | Codec::LamportMerkleBlake2S256PrivShare
        | Codec::LamportMerkleBlake3256Pub
        | Codec::LamportMerkleBlake3256Priv
        | Codec::LamportMerkleBlake3256PrivShare
        | Codec::LamportMerkleShake128Pub
        | Codec::LamportMerkleShake128Priv
        | Codec::LamportMerkleShake128PrivShare
        | Codec::LamportMerkleShake256Pub
        | Codec::LamportMerkleShake256Priv
        | Codec::LamportMerkleShake256PrivShare => {
            Ok(Box::new(lamport_merkle::View::try_from(mk)?))
        }
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
}
/// Builds the verification view for the viewed Multikey.
pub(crate) fn dispatch_verify_view<'a>(
    mk: &'a Multikey,
) -> Result<Box<dyn VerifyView + 'a>, Error> {
    match mk.codec {
        Codec::Bls12381G1PrivShare
        | Codec::Bls12381G1Priv
        | Codec::Bls12381G1Pub
        | Codec::Bls12381G1PubShare
        | Codec::Bls12381G2PrivShare
        | Codec::Bls12381G2Priv
        | Codec::Bls12381G2Pub
        | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(mk)?)),
        Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(mk)?)),
        Codec::Secp256K1Pub | Codec::Secp256K1Priv => Ok(Box::new(secp256k1::View::try_from(mk)?)),
        Codec::SlhDsaSha2128FPub
        | Codec::SlhDsaSha2128SPub
        | Codec::SlhDsaSha2192FPub
        | Codec::SlhDsaSha2192SPub
        | Codec::SlhDsaSha2256FPub
        | Codec::SlhDsaSha2256SPub
        | Codec::SlhDsaShake128FPub
        | Codec::SlhDsaShake128SPub
        | Codec::SlhDsaShake192FPub
        | Codec::SlhDsaShake192SPub
        | Codec::SlhDsaShake256FPub
        | Codec::SlhDsaShake256SPub
        | Codec::SlhDsaSha2128FPriv
        | Codec::SlhDsaSha2128SPriv
        | Codec::SlhDsaSha2192FPriv
        | Codec::SlhDsaSha2192SPriv
        | Codec::SlhDsaSha2256FPriv
        | Codec::SlhDsaSha2256SPriv
        | Codec::SlhDsaShake128FPriv
        | Codec::SlhDsaShake128SPriv
        | Codec::SlhDsaShake192FPriv
        | Codec::SlhDsaShake192SPriv
        | Codec::SlhDsaShake256FPriv
        | Codec::SlhDsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(mk)?)),
        Codec::MlDsa65Pub | Codec::MlDsa65Priv | Codec::MlDsa87Pub | Codec::MlDsa87Priv => {
            Ok(Box::new(ml_dsa::View::try_from(mk)?))
        }
        Codec::Mayo1Pub
        | Codec::Mayo1Priv
        | Codec::Mayo2Pub
        | Codec::Mayo2Priv
        | Codec::Mayo3Pub
        | Codec::Mayo3Priv
        | Codec::Mayo5Pub
        | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(mk)?)),
        Codec::FnDsa512Pub | Codec::FnDsa512Priv | Codec::FnDsa1024Pub | Codec::FnDsa1024Priv => {
            Ok(Box::new(fn_dsa::View::try_from(mk)?))
        }
        Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
            Ok(Box::new(ed25519_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
            Ok(Box::new(ed25519_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
            Ok(Box::new(bls12381_g1_mldsa65::View::try_from(mk)?))
        }
        Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
            Ok(Box::new(bls12381_g1_fndsa512::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
            Ok(Box::new(bls12381_g1_mayo1::View::try_from(mk)?))
        }
        Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
            Ok(Box::new(bls12381_g1_mayo2::View::try_from(mk)?))
        }
        Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
            Ok(Box::new(ed25519_fndsa512::View::try_from(mk)?))
        }
        Codec::P256Pub
        | Codec::P256Priv
        | Codec::P384Pub
        | Codec::P384Priv
        | Codec::P521Pub
        | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(mk)?)),
        Codec::Rsa2048Pub
        | Codec::Rsa2048Priv
        | Codec::Rsa3072Pub
        | Codec::Rsa3072Priv
        | Codec::Rsa4096Pub
        | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportSha3256Pub
        | Codec::LamportSha3256Priv
        | Codec::LamportSha3256PrivShare
        | Codec::LamportSha3384Pub
        | Codec::LamportSha3384Priv
        | Codec::LamportSha3384PrivShare
        | Codec::LamportSha3512Pub
        | Codec::LamportSha3512Priv
        | Codec::LamportSha3512PrivShare
        | Codec::LamportSha2256Pub
        | Codec::LamportSha2256Priv
        | Codec::LamportSha2256PrivShare
        | Codec::LamportSha2384Pub
        | Codec::LamportSha2384Priv
        | Codec::LamportSha2384PrivShare
        | Codec::LamportSha2512Pub
        | Codec::LamportSha2512Priv
        | Codec::LamportSha2512PrivShare
        | Codec::LamportBlake2B512Pub
        | Codec::LamportBlake2B512Priv
        | Codec::LamportBlake2B512PrivShare
        | Codec::LamportBlake2S256Pub
        | Codec::LamportBlake2S256Priv
        | Codec::LamportBlake2S256PrivShare
        | Codec::LamportBlake3256Pub
        | Codec::LamportBlake3256Priv
        | Codec::LamportBlake3256PrivShare
        | Codec::LamportShake128Pub
        | Codec::LamportShake128Priv
        | Codec::LamportShake128PrivShare
        | Codec::LamportShake256Pub
        | Codec::LamportShake256Priv
        | Codec::LamportShake256PrivShare => Ok(Box::new(lamport::View::try_from(mk)?)),
        #[cfg(feature = "lamport")]
        Codec::LamportMerkleSha3256Pub
        | Codec::LamportMerkleSha3256Priv
        | Codec::LamportMerkleSha3256PrivShare
        | Codec::LamportMerkleSha3384Pub
        | Codec::LamportMerkleSha3384Priv
        | Codec::LamportMerkleSha3384PrivShare
        | Codec::LamportMerkleSha3512Pub
        | Codec::LamportMerkleSha3512Priv
        | Codec::LamportMerkleSha3512PrivShare
        | Codec::LamportMerkleSha2256Pub
        | Codec::LamportMerkleSha2256Priv
        | Codec::LamportMerkleSha2256PrivShare
        | Codec::LamportMerkleSha2384Pub
        | Codec::LamportMerkleSha2384Priv
        | Codec::LamportMerkleSha2384PrivShare
        | Codec::LamportMerkleSha2512Pub
        | Codec::LamportMerkleSha2512Priv
        | Codec::LamportMerkleSha2512PrivShare
        | Codec::LamportMerkleBlake2B512Pub
        | Codec::LamportMerkleBlake2B512Priv
        | Codec::LamportMerkleBlake2B512PrivShare
        | Codec::LamportMerkleBlake2S256Pub
        | Codec::LamportMerkleBlake2S256Priv
        | Codec::LamportMerkleBlake2S256PrivShare
        | Codec::LamportMerkleBlake3256Pub
        | Codec::LamportMerkleBlake3256Priv
        | Codec::LamportMerkleBlake3256PrivShare
        | Codec::LamportMerkleShake128Pub
        | Codec::LamportMerkleShake128Priv
        | Codec::LamportMerkleShake128PrivShare
        | Codec::LamportMerkleShake256Pub
        | Codec::LamportMerkleShake256Priv
        | Codec::LamportMerkleShake256PrivShare => {
            Ok(Box::new(lamport_merkle::View::try_from(mk)?))
        }
        #[cfg(feature = "xmss")]
        Codec::XmssSha210256Pub
        | Codec::XmssSha210256Priv
        | Codec::XmssSha216256Pub
        | Codec::XmssSha216256Priv
        | Codec::XmssSha220256Pub
        | Codec::XmssSha220256Priv => Ok(Box::new(xmss::View::try_from(mk)?)),
        Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(xeddsa::View::try_from(mk)?)),
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
}
/// Builds the threshold-disclosure view for the viewed Multikey.
///
/// Construction cannot fail: the built-in disclosure view applies to every
/// codec.
pub(crate) fn dispatch_disclosure_view<'a>(
    mk: &'a Multikey,
) -> Box<dyn ThresholdDisclosureView + 'a> {
    Box::new(threshold_meta::DisclosureView::new(mk))
}
/// Builds the merkle-tree state view for the viewed Multikey.
pub(crate) fn dispatch_merkle_state_view<'a>(
    mk: &'a Multikey,
) -> Result<Box<dyn MerkleStateView + 'a>, Error> {
    #[cfg(feature = "lamport")]
    match mk.codec {
        Codec::LamportMerkleSha3256Pub
        | Codec::LamportMerkleSha3256Priv
        | Codec::LamportMerkleSha3384Pub
        | Codec::LamportMerkleSha3384Priv
        | Codec::LamportMerkleSha3512Pub
        | Codec::LamportMerkleSha3512Priv
        | Codec::LamportMerkleSha2256Pub
        | Codec::LamportMerkleSha2256Priv
        | Codec::LamportMerkleSha2384Pub
        | Codec::LamportMerkleSha2384Priv
        | Codec::LamportMerkleSha2512Pub
        | Codec::LamportMerkleSha2512Priv
        | Codec::LamportMerkleBlake2B512Pub
        | Codec::LamportMerkleBlake2B512Priv
        | Codec::LamportMerkleBlake2S256Pub
        | Codec::LamportMerkleBlake2S256Priv
        | Codec::LamportMerkleBlake3256Pub
        | Codec::LamportMerkleBlake3256Priv
        | Codec::LamportMerkleShake128Pub
        | Codec::LamportMerkleShake128Priv
        | Codec::LamportMerkleShake256Pub
        | Codec::LamportMerkleShake256Priv => Ok(Box::new(lamport_merkle::View::try_from(mk)?)),
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
    #[cfg(not(feature = "lamport"))]
    Err(ConversionsError::UnsupportedCodec(mk.codec).into())
}
