// SPDX-License-Identifier: Apache-2.0
use crate::{
    error::{AttributesError, CipherError, ConversionsError, KdfError, SealError},
    views::{
        bcrypt, bls12381, bls12381_g1_fndsa512, bls12381_g1_mayo1, bls12381_g1_mayo2,
        bls12381_g1_mldsa65, chacha20, classic_mceliece, ed25519, ed25519_fndsa512, ed25519_mayo2,
        ed25519_mldsa65, fn_dsa, frodokem, mayo, ml_dsa, ml_kem, nist_p, rsa, secp256k1, slh_dsa,
        sntrup, threshold_meta, x25519, x25519_frodokem640, x25519_mceliece348864, x25519_mlkem768,
        x25519_sntrup761,
    },
    AttrId, AttrView, CipherAttrView, CipherView, ConvView, DataView, Error, FingerprintView,
    KdfAttrView, KdfView, OpenView, SealView, SignView, ThresholdAttrView, ThresholdDisclosureView,
    ThresholdKeyView, ThresholdView, VerifyView, Views,
};

use ::fn_dsa::{
    sign_key_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard, FN_DSA_LOGN_1024,
    FN_DSA_LOGN_512,
};
use elliptic_curve::sec1::ToSec1Point;
use elliptic_curve::Generate;
use multi_base::Base;
use multi_codec::Codec;
use multi_trait::{EncodeInto, Null, TryDecodeFrom};
use multi_util::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use rand_core::CryptoRng;
use ssh_key::{
    private::{EcdsaKeypair, KeypairData},
    public::{EcdsaPublicKey, KeyData},
    EcdsaCurve, PrivateKey, PublicKey,
};
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroizing;

/// the list of key codecs supported for key generation
pub const KEY_CODECS: [Codec; 7] = [
    Codec::Ed25519Priv,
    Codec::Secp256K1Priv,
    Codec::Bls12381G1Priv,
    Codec::Bls12381G2Priv,
    Codec::P256Priv,
    Codec::P384Priv,
    Codec::P521Priv,
];

/// the list of RSA key codecs supported for key generation
pub const RSA_KEY_CODECS: [Codec; 3] = [Codec::Rsa2048Priv, Codec::Rsa3072Priv, Codec::Rsa4096Priv];

/// the list of FN-DSA key codecs supported for key generation
pub const FN_DSA_KEY_CODECS: [Codec; 2] = [Codec::FnDsa512Priv, Codec::FnDsa1024Priv];

/// the list of ML-DSA key codecs supported for key generation
pub const ML_DSA_KEY_CODECS: [Codec; 2] = [Codec::Mldsa65Priv, Codec::Mldsa87Priv];

/// the list of MAYO key codecs supported for key generation
pub const MAYO_KEY_CODECS: [Codec; 4] = [
    Codec::Mayo1Priv,
    Codec::Mayo2Priv,
    Codec::Mayo3Priv,
    Codec::Mayo5Priv,
];

/// the list of SLH-DSA key codecs (all 12 parameter sets)
pub const SLH_DSA_KEY_CODECS: [Codec; 12] = [
    Codec::SlhdsaSha2128FPriv,
    Codec::SlhdsaSha2128SPriv,
    Codec::SlhdsaSha2192FPriv,
    Codec::SlhdsaSha2192SPriv,
    Codec::SlhdsaSha2256FPriv,
    Codec::SlhdsaSha2256SPriv,
    Codec::SlhdsaShake128FPriv,
    Codec::SlhdsaShake128SPriv,
    Codec::SlhdsaShake192FPriv,
    Codec::SlhdsaShake192SPriv,
    Codec::SlhdsaShake256FPriv,
    Codec::SlhdsaShake256SPriv,
];

/// the list of ML-KEM key codecs supported for key generation
pub const ML_KEM_KEY_CODECS: [Codec; 2] = [Codec::Mlkem768Priv, Codec::Mlkem1024Priv];

/// the list of sntrup key codecs supported for key generation (all sizes)
pub const SNTRUP_KEY_CODECS: [Codec; 5] = [
    Codec::Sntrup761Priv,
    Codec::Sntrup857Priv,
    Codec::Sntrup953Priv,
    Codec::Sntrup1013Priv,
    Codec::Sntrup1277Priv,
];

/// the list of Classic McEliece key codecs supported for key generation
pub const MCELIECE_KEY_CODECS: [Codec; 1] = [Codec::Mceliece348864Priv];

/// the list of FrodoKEM key codecs supported for key generation
pub const FRODOKEM_KEY_CODECS: [Codec; 6] = [
    Codec::FrodoKem640AesPriv,
    Codec::FrodoKem976AesPriv,
    Codec::FrodoKem1344AesPriv,
    Codec::FrodoKem640ShakePriv,
    Codec::FrodoKem976ShakePriv,
    Codec::FrodoKem1344ShakePriv,
];

/// the list of X25519 key codecs supported for key generation
pub const X25519_KEY_CODECS: [Codec; 1] = [Codec::X25519Priv];

/// the list of X25519-sntrup761 hybrid KEM key codecs
pub const X25519_SNTRUP761_KEY_CODECS: [Codec; 1] = [Codec::X25519Sntrup761Priv];

/// the list of X25519-ML-KEM-768 hybrid KEM key codecs
pub const X25519_MLKEM768_KEY_CODECS: [Codec; 1] = [Codec::X25519Mlkem768Priv];

/// the list of Ed25519-MAYO2 hybrid signing key codecs
pub const ED25519_MAYO2_KEY_CODECS: [Codec; 1] = [Codec::Ed25519Mayo2Priv];

/// the list of key share codecs supported
pub const KEY_SHARE_CODECS: [Codec; 4] = [
    Codec::Bls12381G1PubShare,
    Codec::Bls12381G1PrivShare,
    Codec::Bls12381G2PubShare,
    Codec::Bls12381G2PrivShare, /*
                                Codec::LamportSha3256PrivShare,
                                Codec::LamportSha3384PrivShare,
                                Codec::LamportSha3512PrivShare,
                                */
];

/// the multicodec sigil for multikey
pub const SIGIL: Codec = Codec::Multikey;

/// A base encoded Multikey structure
pub type EncodedMultikey = BaseEncoded<Multikey>;

/// The Multikey attributes type
pub type Attributes = BTreeMap<AttrId, Zeroizing<Vec<u8>>>;

/// The main multikey structure
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Multikey {
    /// key codec
    pub(crate) codec: Codec,
    /// the comment for the key
    pub comment: String,
    /// codec-specific attributes, sorted by key
    pub attributes: Attributes,
}

impl CodecInfo for Multikey {
    /// Return that we are a Multikey object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the key coded for the Multikey
    fn codec(&self) -> Codec {
        self.codec
    }
}

impl EncodingInfo for Multikey {
    /// Return the preferred string encoding
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// Same
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl From<Multikey> for Vec<u8> {
    fn from(mk: Multikey) -> Self {
        let mut v = Vec::default();
        // add in the sigil
        v.append(&mut SIGIL.into());
        // add in the key codec
        v.append(&mut mk.codec.into());
        // add in the comment
        v.append(&mut Varbytes::new(mk.comment.as_bytes().to_vec()).into());
        // add in the number of codec-specific attributes
        v.append(&mut Varuint(mk.attributes.len()).into());
        // add in the codec-specific attributes
        mk.attributes.iter().for_each(|(id, attr)| {
            v.append(&mut (*id).into());
            v.append(&mut Varbytes::new(attr.to_vec()).into());
        });
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Multikey {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (mk, _) = Self::try_decode_from(s)?;
        Ok(mk)
    }
}

impl<'a> TryDecodeFrom<'a> for Multikey {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(Error::MissingSigil);
        }
        // decode the key codec
        let (codec, ptr) = Codec::try_decode_from(ptr)?;
        // decode the comment
        let (comment, ptr) = Varbytes::try_decode_from(ptr)?;
        let comment = String::from_utf8(comment.to_inner())?;
        // decode the number of codec-specific attributes
        let (num_attr, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the codec-specific values
        let (attributes, ptr) = match *num_attr {
            0 => (Attributes::default(), ptr),
            _ => {
                let mut attributes = Attributes::new();
                let mut p = ptr;
                for _ in 0..*num_attr {
                    let (id, ptr) = AttrId::try_decode_from(p)?;
                    let (attr, ptr) = Varbytes::try_decode_from(ptr)?;
                    if attributes.insert(id, (*attr).clone().into()).is_some() {
                        return Err(Error::DuplicateAttribute(id.code()));
                    }
                    p = ptr;
                }
                (attributes, p)
            }
        };
        Ok((
            Self {
                codec,
                comment,
                attributes,
            },
            ptr,
        ))
    }
}

impl Null for Multikey {
    fn null() -> Self {
        Self::default()
    }

    fn is_null(&self) -> bool {
        *self == Self::null()
    }
}

impl fmt::Debug for Multikey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // get an attributes view on the key
        let attr = self.attr_view().map_err(|_| fmt::Error)?;

        write!(
            f,
            "{:?} - {:?} - Encrypted: {}",
            SIGIL,
            self.codec(),
            if attr.is_encrypted() { "true" } else { "false" }
        )
    }
}

impl Views for Multikey {
    /// Provide a read-only view of the basic attributes in the viewed Multikey
    fn attr_view<'a>(&'a self) -> Result<Box<dyn AttrView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            Codec::SlhdsaSha2128FPub
            | Codec::SlhdsaSha2128SPub
            | Codec::SlhdsaSha2192FPub
            | Codec::SlhdsaSha2192SPub
            | Codec::SlhdsaSha2256FPub
            | Codec::SlhdsaSha2256SPub
            | Codec::SlhdsaShake128FPub
            | Codec::SlhdsaShake128SPub
            | Codec::SlhdsaShake192FPub
            | Codec::SlhdsaShake192SPub
            | Codec::SlhdsaShake256FPub
            | Codec::SlhdsaShake256SPub
            | Codec::SlhdsaSha2128FPriv
            | Codec::SlhdsaSha2128SPriv
            | Codec::SlhdsaSha2192FPriv
            | Codec::SlhdsaSha2192SPriv
            | Codec::SlhdsaSha2256FPriv
            | Codec::SlhdsaSha2256SPriv
            | Codec::SlhdsaShake128FPriv
            | Codec::SlhdsaShake128SPriv
            | Codec::SlhdsaShake192FPriv
            | Codec::SlhdsaShake192SPriv
            | Codec::SlhdsaShake256FPriv
            | Codec::SlhdsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(self)?)),
            Codec::Mldsa65Pub | Codec::Mldsa65Priv | Codec::Mldsa87Pub | Codec::Mldsa87Priv => {
                Ok(Box::new(ml_dsa::View::try_from(self)?))
            }
            Codec::Mayo1Pub
            | Codec::Mayo1Priv
            | Codec::Mayo2Pub
            | Codec::Mayo2Priv
            | Codec::Mayo3Pub
            | Codec::Mayo3Priv
            | Codec::Mayo5Pub
            | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(self)?)),
            Codec::FnDsa512Pub
            | Codec::FnDsa512Priv
            | Codec::FnDsa1024Pub
            | Codec::FnDsa1024Priv => Ok(Box::new(fn_dsa::View::try_from(self)?)),
            Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(ml_kem::View::try_from(self)?)),
            Codec::Sntrup761Pub
            | Codec::Sntrup761Priv
            | Codec::Sntrup857Pub
            | Codec::Sntrup857Priv
            | Codec::Sntrup953Pub
            | Codec::Sntrup953Priv
            | Codec::Sntrup1013Pub
            | Codec::Sntrup1013Priv
            | Codec::Sntrup1277Pub
            | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(self)?)),
            Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
                Ok(Box::new(classic_mceliece::View::try_from(self)?))
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
            | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(self)?)),
            Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(self)?)),
            Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
                Ok(Box::new(x25519_sntrup761::View::try_from(self)?))
            }
            Codec::X25519Frodokem640AesPub
            | Codec::X25519Frodokem640AesPriv
            | Codec::X25519Frodokem640ShakePub
            | Codec::X25519Frodokem640ShakePriv => {
                Ok(Box::new(x25519_frodokem640::View::try_from(self)?))
            }
            Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
                Ok(Box::new(x25519_mceliece348864::View::try_from(self)?))
            }
            Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
                Ok(Box::new(x25519_mlkem768::View::try_from(self)?))
            }
            Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
                Ok(Box::new(ed25519_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
                Ok(Box::new(ed25519_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
                Ok(Box::new(bls12381_g1_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
                Ok(Box::new(bls12381_g1_fndsa512::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
                Ok(Box::new(bls12381_g1_mayo1::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
                Ok(Box::new(bls12381_g1_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
                Ok(Box::new(ed25519_fndsa512::View::try_from(self)?))
            }
            Codec::P256Pub
            | Codec::P256Priv
            | Codec::P384Pub
            | Codec::P384Priv
            | Codec::P521Pub
            | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(self)?)),
            Codec::Rsa2048Pub
            | Codec::Rsa2048Priv
            | Codec::Rsa3072Pub
            | Codec::Rsa3072Priv
            | Codec::Rsa4096Pub
            | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(self)?)),
            _ => Err(AttributesError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of the cipher attributes in the viewed Multikey
    fn cipher_attr_view<'a>(&'a self) -> Result<Box<dyn CipherAttrView + 'a>, Error> {
        let codec = if let Some(bytes) = self.attributes.get(&AttrId::CipherCodec) {
            Codec::try_from(bytes.as_slice())?
        } else {
            self.codec
        };
        match codec {
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            _ => Err(CipherError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view to key data in the viewed Multikey
    fn data_view<'a>(&'a self) -> Result<Box<dyn DataView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            Codec::SlhdsaSha2128FPub
            | Codec::SlhdsaSha2128SPub
            | Codec::SlhdsaSha2192FPub
            | Codec::SlhdsaSha2192SPub
            | Codec::SlhdsaSha2256FPub
            | Codec::SlhdsaSha2256SPub
            | Codec::SlhdsaShake128FPub
            | Codec::SlhdsaShake128SPub
            | Codec::SlhdsaShake192FPub
            | Codec::SlhdsaShake192SPub
            | Codec::SlhdsaShake256FPub
            | Codec::SlhdsaShake256SPub
            | Codec::SlhdsaSha2128FPriv
            | Codec::SlhdsaSha2128SPriv
            | Codec::SlhdsaSha2192FPriv
            | Codec::SlhdsaSha2192SPriv
            | Codec::SlhdsaSha2256FPriv
            | Codec::SlhdsaSha2256SPriv
            | Codec::SlhdsaShake128FPriv
            | Codec::SlhdsaShake128SPriv
            | Codec::SlhdsaShake192FPriv
            | Codec::SlhdsaShake192SPriv
            | Codec::SlhdsaShake256FPriv
            | Codec::SlhdsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(self)?)),
            Codec::Mldsa65Pub | Codec::Mldsa65Priv | Codec::Mldsa87Pub | Codec::Mldsa87Priv => {
                Ok(Box::new(ml_dsa::View::try_from(self)?))
            }
            Codec::Mayo1Pub
            | Codec::Mayo1Priv
            | Codec::Mayo2Pub
            | Codec::Mayo2Priv
            | Codec::Mayo3Pub
            | Codec::Mayo3Priv
            | Codec::Mayo5Pub
            | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(self)?)),
            Codec::FnDsa512Pub
            | Codec::FnDsa512Priv
            | Codec::FnDsa1024Pub
            | Codec::FnDsa1024Priv => Ok(Box::new(fn_dsa::View::try_from(self)?)),
            Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(ml_kem::View::try_from(self)?)),
            Codec::Sntrup761Pub
            | Codec::Sntrup761Priv
            | Codec::Sntrup857Pub
            | Codec::Sntrup857Priv
            | Codec::Sntrup953Pub
            | Codec::Sntrup953Priv
            | Codec::Sntrup1013Pub
            | Codec::Sntrup1013Priv
            | Codec::Sntrup1277Pub
            | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(self)?)),
            Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
                Ok(Box::new(classic_mceliece::View::try_from(self)?))
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
            | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(self)?)),
            Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(self)?)),
            Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
                Ok(Box::new(x25519_sntrup761::View::try_from(self)?))
            }
            Codec::X25519Frodokem640AesPub
            | Codec::X25519Frodokem640AesPriv
            | Codec::X25519Frodokem640ShakePub
            | Codec::X25519Frodokem640ShakePriv => {
                Ok(Box::new(x25519_frodokem640::View::try_from(self)?))
            }
            Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
                Ok(Box::new(x25519_mceliece348864::View::try_from(self)?))
            }
            Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
                Ok(Box::new(x25519_mlkem768::View::try_from(self)?))
            }
            Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
                Ok(Box::new(ed25519_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
                Ok(Box::new(ed25519_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
                Ok(Box::new(bls12381_g1_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
                Ok(Box::new(bls12381_g1_fndsa512::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
                Ok(Box::new(bls12381_g1_mayo1::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
                Ok(Box::new(bls12381_g1_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
                Ok(Box::new(ed25519_fndsa512::View::try_from(self)?))
            }
            Codec::P256Pub
            | Codec::P256Priv
            | Codec::P384Pub
            | Codec::P384Priv
            | Codec::P521Pub
            | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(self)?)),
            Codec::Rsa2048Pub
            | Codec::Rsa2048Priv
            | Codec::Rsa3072Pub
            | Codec::Rsa3072Priv
            | Codec::Rsa4096Pub
            | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of the kdf attributes in the viewed Multikey
    fn kdf_attr_view<'a>(&'a self) -> Result<Box<dyn KdfAttrView + 'a>, Error> {
        let codec = if let Some(bytes) = self.attributes.get(&AttrId::KdfCodec) {
            Codec::try_from(bytes.as_slice())?
        } else {
            self.codec
        };
        match codec {
            Codec::BcryptPbkdf => Ok(Box::new(bcrypt::View::try_from(self)?)),
            _ => Err(KdfError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of the threshold attributes in the viewed Multikey
    fn threshold_attr_view<'a>(&'a self) -> Result<Box<dyn ThresholdAttrView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519ThreshPrivShare
            | Codec::P256ThreshPrivShare
            | Codec::P384ThreshPrivShare
            | Codec::Secp256K1ThreshPrivShare
            | Codec::Bls12381ThreshPrivShare
            | Codec::Ed448ThreshPrivShare => {
                Ok(Box::new(crate::views::dkg_threshold::View::try_from(self)?))
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of higher-level threshold key metadata in the viewed Multikey
    fn threshold_key_view<'a>(&'a self) -> Result<Box<dyn ThresholdKeyView + 'a>, Error> {
        match self.codec {
            Codec::Ed25519ThreshPrivShare
            | Codec::P256ThreshPrivShare
            | Codec::P384ThreshPrivShare
            | Codec::Secp256K1ThreshPrivShare
            | Codec::Bls12381ThreshPrivShare
            | Codec::Ed448ThreshPrivShare => {
                Ok(Box::new(crate::views::dkg_threshold::View::try_from(self)?))
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do encryption/decryption of the viewed Multikey
    fn cipher_view<'a>(&'a self, cipher: &'a Multikey) -> Result<Box<dyn CipherView + 'a>, Error> {
        match cipher.codec {
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::new(self, cipher))),
            _ => Err(CipherError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do key conversions from the viewe Multikey
    fn conv_view<'a>(&'a self) -> Result<Box<dyn ConvView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::SlhdsaSha2128FPub
            | Codec::SlhdsaSha2128SPub
            | Codec::SlhdsaSha2192FPub
            | Codec::SlhdsaSha2192SPub
            | Codec::SlhdsaSha2256FPub
            | Codec::SlhdsaSha2256SPub
            | Codec::SlhdsaShake128FPub
            | Codec::SlhdsaShake128SPub
            | Codec::SlhdsaShake192FPub
            | Codec::SlhdsaShake192SPub
            | Codec::SlhdsaShake256FPub
            | Codec::SlhdsaShake256SPub
            | Codec::SlhdsaSha2128FPriv
            | Codec::SlhdsaSha2128SPriv
            | Codec::SlhdsaSha2192FPriv
            | Codec::SlhdsaSha2192SPriv
            | Codec::SlhdsaSha2256FPriv
            | Codec::SlhdsaSha2256SPriv
            | Codec::SlhdsaShake128FPriv
            | Codec::SlhdsaShake128SPriv
            | Codec::SlhdsaShake192FPriv
            | Codec::SlhdsaShake192SPriv
            | Codec::SlhdsaShake256FPriv
            | Codec::SlhdsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(self)?)),
            Codec::Mldsa65Pub | Codec::Mldsa65Priv | Codec::Mldsa87Pub | Codec::Mldsa87Priv => {
                Ok(Box::new(ml_dsa::View::try_from(self)?))
            }
            Codec::Mayo1Pub
            | Codec::Mayo1Priv
            | Codec::Mayo2Pub
            | Codec::Mayo2Priv
            | Codec::Mayo3Pub
            | Codec::Mayo3Priv
            | Codec::Mayo5Pub
            | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(self)?)),
            Codec::FnDsa512Pub
            | Codec::FnDsa512Priv
            | Codec::FnDsa1024Pub
            | Codec::FnDsa1024Priv => Ok(Box::new(fn_dsa::View::try_from(self)?)),
            Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(ml_kem::View::try_from(self)?)),
            Codec::Sntrup761Pub
            | Codec::Sntrup761Priv
            | Codec::Sntrup857Pub
            | Codec::Sntrup857Priv
            | Codec::Sntrup953Pub
            | Codec::Sntrup953Priv
            | Codec::Sntrup1013Pub
            | Codec::Sntrup1013Priv
            | Codec::Sntrup1277Pub
            | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(self)?)),
            Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
                Ok(Box::new(classic_mceliece::View::try_from(self)?))
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
            | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(self)?)),
            Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(self)?)),
            Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
                Ok(Box::new(x25519_sntrup761::View::try_from(self)?))
            }
            Codec::X25519Frodokem640AesPub
            | Codec::X25519Frodokem640AesPriv
            | Codec::X25519Frodokem640ShakePub
            | Codec::X25519Frodokem640ShakePriv => {
                Ok(Box::new(x25519_frodokem640::View::try_from(self)?))
            }
            Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
                Ok(Box::new(x25519_mceliece348864::View::try_from(self)?))
            }
            Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
                Ok(Box::new(x25519_mlkem768::View::try_from(self)?))
            }
            Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
                Ok(Box::new(ed25519_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
                Ok(Box::new(ed25519_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
                Ok(Box::new(bls12381_g1_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
                Ok(Box::new(bls12381_g1_fndsa512::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
                Ok(Box::new(bls12381_g1_mayo1::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
                Ok(Box::new(bls12381_g1_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
                Ok(Box::new(ed25519_fndsa512::View::try_from(self)?))
            }
            Codec::P256Pub
            | Codec::P256Priv
            | Codec::P384Pub
            | Codec::P384Priv
            | Codec::P521Pub
            | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(self)?)),
            Codec::Rsa2048Pub
            | Codec::Rsa2048Priv
            | Codec::Rsa3072Pub
            | Codec::Rsa3072Priv
            | Codec::Rsa4096Pub
            | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do key conversions from the viewe Multikey
    fn fingerprint_view<'a>(&'a self) -> Result<Box<dyn FingerprintView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            Codec::SlhdsaSha2128FPub
            | Codec::SlhdsaSha2128SPub
            | Codec::SlhdsaSha2192FPub
            | Codec::SlhdsaSha2192SPub
            | Codec::SlhdsaSha2256FPub
            | Codec::SlhdsaSha2256SPub
            | Codec::SlhdsaShake128FPub
            | Codec::SlhdsaShake128SPub
            | Codec::SlhdsaShake192FPub
            | Codec::SlhdsaShake192SPub
            | Codec::SlhdsaShake256FPub
            | Codec::SlhdsaShake256SPub
            | Codec::SlhdsaSha2128FPriv
            | Codec::SlhdsaSha2128SPriv
            | Codec::SlhdsaSha2192FPriv
            | Codec::SlhdsaSha2192SPriv
            | Codec::SlhdsaSha2256FPriv
            | Codec::SlhdsaSha2256SPriv
            | Codec::SlhdsaShake128FPriv
            | Codec::SlhdsaShake128SPriv
            | Codec::SlhdsaShake192FPriv
            | Codec::SlhdsaShake192SPriv
            | Codec::SlhdsaShake256FPriv
            | Codec::SlhdsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(self)?)),
            Codec::Mldsa65Pub | Codec::Mldsa65Priv | Codec::Mldsa87Pub | Codec::Mldsa87Priv => {
                Ok(Box::new(ml_dsa::View::try_from(self)?))
            }
            Codec::Mayo1Pub
            | Codec::Mayo1Priv
            | Codec::Mayo2Pub
            | Codec::Mayo2Priv
            | Codec::Mayo3Pub
            | Codec::Mayo3Priv
            | Codec::Mayo5Pub
            | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(self)?)),
            Codec::FnDsa512Pub
            | Codec::FnDsa512Priv
            | Codec::FnDsa1024Pub
            | Codec::FnDsa1024Priv => Ok(Box::new(fn_dsa::View::try_from(self)?)),
            Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(ml_kem::View::try_from(self)?)),
            Codec::Sntrup761Pub
            | Codec::Sntrup761Priv
            | Codec::Sntrup857Pub
            | Codec::Sntrup857Priv
            | Codec::Sntrup953Pub
            | Codec::Sntrup953Priv
            | Codec::Sntrup1013Pub
            | Codec::Sntrup1013Priv
            | Codec::Sntrup1277Pub
            | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(self)?)),
            Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
                Ok(Box::new(classic_mceliece::View::try_from(self)?))
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
            | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(self)?)),
            Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(self)?)),
            Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
                Ok(Box::new(x25519_sntrup761::View::try_from(self)?))
            }
            Codec::X25519Frodokem640AesPub
            | Codec::X25519Frodokem640AesPriv
            | Codec::X25519Frodokem640ShakePub
            | Codec::X25519Frodokem640ShakePriv => {
                Ok(Box::new(x25519_frodokem640::View::try_from(self)?))
            }
            Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
                Ok(Box::new(x25519_mceliece348864::View::try_from(self)?))
            }
            Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
                Ok(Box::new(x25519_mlkem768::View::try_from(self)?))
            }
            Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
                Ok(Box::new(ed25519_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
                Ok(Box::new(ed25519_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
                Ok(Box::new(bls12381_g1_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
                Ok(Box::new(bls12381_g1_fndsa512::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
                Ok(Box::new(bls12381_g1_mayo1::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
                Ok(Box::new(bls12381_g1_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
                Ok(Box::new(ed25519_fndsa512::View::try_from(self)?))
            }
            Codec::P256Pub
            | Codec::P256Priv
            | Codec::P384Pub
            | Codec::P384Priv
            | Codec::P521Pub
            | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(self)?)),
            Codec::Rsa2048Pub
            | Codec::Rsa2048Priv
            | Codec::Rsa3072Pub
            | Codec::Rsa3072Priv
            | Codec::Rsa4096Pub
            | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do kdf operations from the viewed Multikey
    fn kdf_view<'a>(&'a self, kdf: &'a Multikey) -> Result<Box<dyn KdfView + 'a>, Error> {
        match kdf.codec {
            Codec::BcryptPbkdf => Ok(Box::new(bcrypt::View::new(self, kdf))),
            _ => Err(KdfError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to seal (encrypt) plaintext
    fn seal_view<'a>(&'a self) -> Result<Box<dyn SealView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1Pub
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2Priv => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(ml_kem::View::try_from(self)?)),
            Codec::Sntrup761Pub
            | Codec::Sntrup761Priv
            | Codec::Sntrup857Pub
            | Codec::Sntrup857Priv
            | Codec::Sntrup953Pub
            | Codec::Sntrup953Priv
            | Codec::Sntrup1013Pub
            | Codec::Sntrup1013Priv
            | Codec::Sntrup1277Pub
            | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(self)?)),
            Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
                Ok(Box::new(classic_mceliece::View::try_from(self)?))
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
            | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(self)?)),
            Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(self)?)),
            Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
                Ok(Box::new(x25519_sntrup761::View::try_from(self)?))
            }
            Codec::X25519Frodokem640AesPub
            | Codec::X25519Frodokem640AesPriv
            | Codec::X25519Frodokem640ShakePub
            | Codec::X25519Frodokem640ShakePriv => {
                Ok(Box::new(x25519_frodokem640::View::try_from(self)?))
            }
            Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
                Ok(Box::new(x25519_mceliece348864::View::try_from(self)?))
            }
            Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
                Ok(Box::new(x25519_mlkem768::View::try_from(self)?))
            }
            Codec::Rsa2048Pub
            | Codec::Rsa2048Priv
            | Codec::Rsa3072Pub
            | Codec::Rsa3072Priv
            | Codec::Rsa4096Pub
            | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(self)?)),
            Codec::P256Pub
            | Codec::P256Priv
            | Codec::P384Pub
            | Codec::P384Priv
            | Codec::P521Pub
            | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            _ => Err(SealError::NotEncryptionKey.into()),
        }
    }

    /// Provide an interface to open (decrypt) sealed data
    fn open_view<'a>(&'a self) -> Result<Box<dyn OpenView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1Pub
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2Priv => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Mlkem768Pub
            | Codec::Mlkem768Priv
            | Codec::Mlkem1024Pub
            | Codec::Mlkem1024Priv => Ok(Box::new(ml_kem::View::try_from(self)?)),
            Codec::Sntrup761Pub
            | Codec::Sntrup761Priv
            | Codec::Sntrup857Pub
            | Codec::Sntrup857Priv
            | Codec::Sntrup953Pub
            | Codec::Sntrup953Priv
            | Codec::Sntrup1013Pub
            | Codec::Sntrup1013Priv
            | Codec::Sntrup1277Pub
            | Codec::Sntrup1277Priv => Ok(Box::new(sntrup::View::try_from(self)?)),
            Codec::Mceliece348864Pub | Codec::Mceliece348864Priv => {
                Ok(Box::new(classic_mceliece::View::try_from(self)?))
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
            | Codec::FrodoKem1344ShakePriv => Ok(Box::new(frodokem::View::try_from(self)?)),
            Codec::X25519Pub | Codec::X25519Priv => Ok(Box::new(x25519::View::try_from(self)?)),
            Codec::X25519Sntrup761Pub | Codec::X25519Sntrup761Priv => {
                Ok(Box::new(x25519_sntrup761::View::try_from(self)?))
            }
            Codec::X25519Frodokem640AesPub
            | Codec::X25519Frodokem640AesPriv
            | Codec::X25519Frodokem640ShakePub
            | Codec::X25519Frodokem640ShakePriv => {
                Ok(Box::new(x25519_frodokem640::View::try_from(self)?))
            }
            Codec::X25519Mceliece348864Pub | Codec::X25519Mceliece348864Priv => {
                Ok(Box::new(x25519_mceliece348864::View::try_from(self)?))
            }
            Codec::X25519Mlkem768Pub | Codec::X25519Mlkem768Priv => {
                Ok(Box::new(x25519_mlkem768::View::try_from(self)?))
            }
            Codec::Rsa2048Pub
            | Codec::Rsa2048Priv
            | Codec::Rsa3072Pub
            | Codec::Rsa3072Priv
            | Codec::Rsa4096Pub
            | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(self)?)),
            Codec::P256Pub
            | Codec::P256Priv
            | Codec::P384Pub
            | Codec::P384Priv
            | Codec::P521Pub
            | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            _ => Err(SealError::NotEncryptionKey.into()),
        }
    }

    /// Provide an interface to sign a message and return a Multisig
    fn sign_view<'a>(&'a self) -> Result<Box<dyn SignView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::SlhdsaSha2128FPub
            | Codec::SlhdsaSha2128SPub
            | Codec::SlhdsaSha2192FPub
            | Codec::SlhdsaSha2192SPub
            | Codec::SlhdsaSha2256FPub
            | Codec::SlhdsaSha2256SPub
            | Codec::SlhdsaShake128FPub
            | Codec::SlhdsaShake128SPub
            | Codec::SlhdsaShake192FPub
            | Codec::SlhdsaShake192SPub
            | Codec::SlhdsaShake256FPub
            | Codec::SlhdsaShake256SPub
            | Codec::SlhdsaSha2128FPriv
            | Codec::SlhdsaSha2128SPriv
            | Codec::SlhdsaSha2192FPriv
            | Codec::SlhdsaSha2192SPriv
            | Codec::SlhdsaSha2256FPriv
            | Codec::SlhdsaSha2256SPriv
            | Codec::SlhdsaShake128FPriv
            | Codec::SlhdsaShake128SPriv
            | Codec::SlhdsaShake192FPriv
            | Codec::SlhdsaShake192SPriv
            | Codec::SlhdsaShake256FPriv
            | Codec::SlhdsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(self)?)),
            Codec::Mldsa65Pub | Codec::Mldsa65Priv | Codec::Mldsa87Pub | Codec::Mldsa87Priv => {
                Ok(Box::new(ml_dsa::View::try_from(self)?))
            }
            Codec::Mayo1Pub
            | Codec::Mayo1Priv
            | Codec::Mayo2Pub
            | Codec::Mayo2Priv
            | Codec::Mayo3Pub
            | Codec::Mayo3Priv
            | Codec::Mayo5Pub
            | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(self)?)),
            Codec::FnDsa512Pub
            | Codec::FnDsa512Priv
            | Codec::FnDsa1024Pub
            | Codec::FnDsa1024Priv => Ok(Box::new(fn_dsa::View::try_from(self)?)),
            Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
                Ok(Box::new(ed25519_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
                Ok(Box::new(ed25519_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
                Ok(Box::new(bls12381_g1_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
                Ok(Box::new(bls12381_g1_fndsa512::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
                Ok(Box::new(bls12381_g1_mayo1::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
                Ok(Box::new(bls12381_g1_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
                Ok(Box::new(ed25519_fndsa512::View::try_from(self)?))
            }
            Codec::P256Pub
            | Codec::P256Priv
            | Codec::P384Pub
            | Codec::P384Priv
            | Codec::P521Pub
            | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(self)?)),
            Codec::Rsa2048Pub
            | Codec::Rsa2048Priv
            | Codec::Rsa3072Pub
            | Codec::Rsa3072Priv
            | Codec::Rsa4096Pub
            | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do threshold operations on the Multikey
    fn threshold_view<'a>(&'a self) -> Result<Box<dyn ThresholdView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1Priv | Codec::Bls12381G2Priv => {
                Ok(Box::new(bls12381::View::try_from(self)?))
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to verify a Multisig and optional message
    fn verify_view<'a>(&'a self) -> Result<Box<dyn VerifyView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G1PubShare
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub
            | Codec::Bls12381G2PubShare => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::SlhdsaSha2128FPub
            | Codec::SlhdsaSha2128SPub
            | Codec::SlhdsaSha2192FPub
            | Codec::SlhdsaSha2192SPub
            | Codec::SlhdsaSha2256FPub
            | Codec::SlhdsaSha2256SPub
            | Codec::SlhdsaShake128FPub
            | Codec::SlhdsaShake128SPub
            | Codec::SlhdsaShake192FPub
            | Codec::SlhdsaShake192SPub
            | Codec::SlhdsaShake256FPub
            | Codec::SlhdsaShake256SPub
            | Codec::SlhdsaSha2128FPriv
            | Codec::SlhdsaSha2128SPriv
            | Codec::SlhdsaSha2192FPriv
            | Codec::SlhdsaSha2192SPriv
            | Codec::SlhdsaSha2256FPriv
            | Codec::SlhdsaSha2256SPriv
            | Codec::SlhdsaShake128FPriv
            | Codec::SlhdsaShake128SPriv
            | Codec::SlhdsaShake192FPriv
            | Codec::SlhdsaShake192SPriv
            | Codec::SlhdsaShake256FPriv
            | Codec::SlhdsaShake256SPriv => Ok(Box::new(slh_dsa::View::try_from(self)?)),
            Codec::Mldsa65Pub | Codec::Mldsa65Priv | Codec::Mldsa87Pub | Codec::Mldsa87Priv => {
                Ok(Box::new(ml_dsa::View::try_from(self)?))
            }
            Codec::Mayo1Pub
            | Codec::Mayo1Priv
            | Codec::Mayo2Pub
            | Codec::Mayo2Priv
            | Codec::Mayo3Pub
            | Codec::Mayo3Priv
            | Codec::Mayo5Pub
            | Codec::Mayo5Priv => Ok(Box::new(mayo::View::try_from(self)?)),
            Codec::FnDsa512Pub
            | Codec::FnDsa512Priv
            | Codec::FnDsa1024Pub
            | Codec::FnDsa1024Priv => Ok(Box::new(fn_dsa::View::try_from(self)?)),
            Codec::Ed25519Mayo2Pub | Codec::Ed25519Mayo2Priv => {
                Ok(Box::new(ed25519_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Mldsa65Pub | Codec::Ed25519Mldsa65Priv => {
                Ok(Box::new(ed25519_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Mldsa65Pub | Codec::Bls12381G1Mldsa65Priv => {
                Ok(Box::new(bls12381_g1_mldsa65::View::try_from(self)?))
            }
            Codec::Bls12381G1Fndsa512Pub | Codec::Bls12381G1Fndsa512Priv => {
                Ok(Box::new(bls12381_g1_fndsa512::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo1Pub | Codec::Bls12381G1Mayo1Priv => {
                Ok(Box::new(bls12381_g1_mayo1::View::try_from(self)?))
            }
            Codec::Bls12381G1Mayo2Pub | Codec::Bls12381G1Mayo2Priv => {
                Ok(Box::new(bls12381_g1_mayo2::View::try_from(self)?))
            }
            Codec::Ed25519Fndsa512Pub | Codec::Ed25519Fndsa512Priv => {
                Ok(Box::new(ed25519_fndsa512::View::try_from(self)?))
            }
            Codec::P256Pub
            | Codec::P256Priv
            | Codec::P384Pub
            | Codec::P384Priv
            | Codec::P521Pub
            | Codec::P521Priv => Ok(Box::new(nist_p::View::try_from(self)?)),
            Codec::Rsa2048Pub
            | Codec::Rsa2048Priv
            | Codec::Rsa3072Pub
            | Codec::Rsa3072Priv
            | Codec::Rsa4096Pub
            | Codec::Rsa4096Priv => Ok(Box::new(rsa::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface for threshold disclosure mode operations
    fn disclosure_view<'a>(&'a self) -> Result<Box<dyn ThresholdDisclosureView + 'a>, Error> {
        Ok(Box::new(threshold_meta::DisclosureView::new(self)))
    }
}

/// Multikey builder constructs private keys only. If you need a public key you
/// must first generate a priate key and then get the public key from that.
#[derive(Clone, Default)]
pub struct Builder {
    codec: Codec,
    comment: Option<String>,
    base_encoding: Option<Base>,
    attributes: Option<Attributes>,
    shares: Option<Vec<Multikey>>,
}

impl Builder {
    /// create a new multikey with the given codec
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec,
            ..Default::default()
        }
    }

    /// new builder from random bytes source
    pub fn new_from_random_bytes(codec: Codec, rng: &mut impl CryptoRng) -> Result<Self, Error> {
        let key_bytes = match codec {
            Codec::Ed25519Priv => ed25519_dalek::SigningKey::generate(rng).to_bytes().to_vec(),
            Codec::P256Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP256)
                .map_err(|e| ConversionsError::Ssh(e.into()))?
                .private_key_bytes()
                .to_vec(),
            Codec::P384Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP384)
                .map_err(|e| ConversionsError::Ssh(e.into()))?
                .private_key_bytes()
                .to_vec(),
            Codec::P521Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP521)
                .map_err(|e| ConversionsError::Ssh(e.into()))?
                .private_key_bytes()
                .to_vec(),
            Codec::Secp256K1Priv => k256::SecretKey::generate_from_rng(rng).to_bytes().to_vec(),
            Codec::Bls12381G1Priv => blsful::Bls12381G1::new_secret_key()
                .to_be_bytes()
                .as_slice()
                .to_vec(),
            Codec::Bls12381G2Priv => blsful::Bls12381G2::new_secret_key()
                .to_be_bytes()
                .as_slice()
                .to_vec(),
            Codec::FnDsa512Priv => {
                let mut kg = KeyPairGeneratorStandard::default();
                let mut sign_key = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
                let mut vrfy_key = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
                kg.keygen(
                    FN_DSA_LOGN_512,
                    &mut rand_core_06::OsRng,
                    &mut sign_key,
                    &mut vrfy_key,
                );
                sign_key
            }
            Codec::FnDsa1024Priv => {
                let mut kg = KeyPairGeneratorStandard::default();
                let mut sign_key = vec![0u8; sign_key_size(FN_DSA_LOGN_1024)];
                let mut vrfy_key = vec![0u8; vrfy_key_size(FN_DSA_LOGN_1024)];
                kg.keygen(
                    FN_DSA_LOGN_1024,
                    &mut rand_core_06::OsRng,
                    &mut sign_key,
                    &mut vrfy_key,
                );
                sign_key
            }
            Codec::Mldsa65Priv | Codec::Mldsa87Priv => {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::Mayo1Priv | Codec::Mayo2Priv => {
                let mut seed = [0u8; 24];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::Mayo3Priv => {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::Mayo5Priv => {
                let mut seed = [0u8; 40];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::Mlkem768Priv | Codec::Mlkem1024Priv => {
                // 64-byte seed: d (32) || z (32)
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::Sntrup761Priv
            | Codec::Sntrup857Priv
            | Codec::Sntrup953Priv
            | Codec::Sntrup1013Priv
            | Codec::Sntrup1277Priv => {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::Mceliece348864Priv => {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::FrodoKem640AesPriv
            | Codec::FrodoKem976AesPriv
            | Codec::FrodoKem1344AesPriv
            | Codec::FrodoKem640ShakePriv
            | Codec::FrodoKem976ShakePriv
            | Codec::FrodoKem1344ShakePriv => frodokem::generate_private_key(codec)?.to_vec(),
            Codec::X25519Priv => {
                let mut secret = [0u8; 32];
                rng.fill_bytes(&mut secret);
                secret.to_vec()
            }
            Codec::X25519Sntrup761Priv => {
                // x25519_seed (32) || sntrup761_seed (32) = 64 bytes
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::X25519Mceliece348864Priv => {
                // x25519_seed (32) || mceliece_seed (32) = 64 bytes
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::X25519Frodokem640AesPriv | Codec::X25519Frodokem640ShakePriv => {
                // x25519_seed (32) || frodokem full secret key
                x25519_frodokem640::generate_private_key(codec)
            }
            Codec::X25519Mlkem768Priv => {
                // x25519_seed (32) || ml_kem_d (32) || ml_kem_z (32) = 96 bytes
                let mut seed = [0u8; 96];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::Ed25519Mayo2Priv => {
                // ed25519_seed (32) || mayo2_seed (24) = 56 bytes
                let mut seed = [0u8; 56];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::Ed25519Mldsa65Priv => {
                // ed25519_seed (32) || ml_dsa_seed (32) = 64 bytes
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            Codec::Bls12381G1Mldsa65Priv => {
                // bls_g1_secret (32) || ml_dsa_65_seed (32) = 64 bytes
                let mut out = Vec::with_capacity(64);
                out.extend_from_slice(&blsful::Bls12381G1::new_secret_key().to_be_bytes());
                let mut mldsa_seed = [0u8; 32];
                rng.fill_bytes(&mut mldsa_seed);
                out.extend_from_slice(&mldsa_seed);
                out
            }
            Codec::Bls12381G1Fndsa512Priv => {
                // bls_g1_secret (32) || fn_dsa_512_signing_key
                let mut out = Vec::new();
                out.extend_from_slice(&blsful::Bls12381G1::new_secret_key().to_be_bytes());
                let mut kg = KeyPairGeneratorStandard::default();
                let mut sign_key = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
                let mut vrfy_key = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
                kg.keygen(
                    FN_DSA_LOGN_512,
                    &mut rand_core_06::OsRng,
                    &mut sign_key,
                    &mut vrfy_key,
                );
                out.extend_from_slice(&sign_key);
                out
            }
            Codec::Bls12381G1Mayo1Priv | Codec::Bls12381G1Mayo2Priv => {
                // bls_g1_secret (32) || mayo_seed (24) = 56 bytes
                let mut out = Vec::with_capacity(56);
                out.extend_from_slice(&blsful::Bls12381G1::new_secret_key().to_be_bytes());
                let mut mayo_seed = [0u8; 24];
                rng.fill_bytes(&mut mayo_seed);
                out.extend_from_slice(&mayo_seed);
                out
            }
            Codec::Ed25519Fndsa512Priv => {
                // ed25519_seed (32) || fn_dsa_512_signing_key
                let mut ed_seed = [0u8; 32];
                rng.fill_bytes(&mut ed_seed);
                let mut kg = KeyPairGeneratorStandard::default();
                let mut sign_key = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
                let mut vrfy_key = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
                kg.keygen(
                    FN_DSA_LOGN_512,
                    &mut rand_core_06::OsRng,
                    &mut sign_key,
                    &mut vrfy_key,
                );
                let mut out = Vec::with_capacity(32 + sign_key.len());
                out.extend_from_slice(&ed_seed);
                out.extend_from_slice(&sign_key);
                out
            }
            Codec::Rsa2048Priv => {
                let key = ::rsa::RsaPrivateKey::new(&mut rsa::OsRng, 2048)
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                ::rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&key)
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?
                    .as_bytes()
                    .to_vec()
            }
            Codec::Rsa3072Priv => {
                let key = ::rsa::RsaPrivateKey::new(&mut rsa::OsRng, 3072)
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                ::rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&key)
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?
                    .as_bytes()
                    .to_vec()
            }
            Codec::Rsa4096Priv => {
                let key = ::rsa::RsaPrivateKey::new(&mut rsa::OsRng, 4096)
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
                ::rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&key)
                    .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?
                    .as_bytes()
                    .to_vec()
            }
            Codec::SlhdsaSha2128FPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Sha2_128f>(),
            Codec::SlhdsaSha2128SPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Sha2_128s>(),
            Codec::SlhdsaSha2192FPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Sha2_192f>(),
            Codec::SlhdsaSha2192SPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Sha2_192s>(),
            Codec::SlhdsaSha2256FPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Sha2_256f>(),
            Codec::SlhdsaSha2256SPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Sha2_256s>(),
            Codec::SlhdsaShake128FPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Shake128f>(),
            Codec::SlhdsaShake128SPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Shake128s>(),
            Codec::SlhdsaShake192FPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Shake192f>(),
            Codec::SlhdsaShake192SPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Shake192s>(),
            Codec::SlhdsaShake256FPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Shake256f>(),
            Codec::SlhdsaShake256SPriv => slh_dsa::gen_slh_dsa_key::<::slh_dsa::Shake256s>(),
            _ => return Err(ConversionsError::UnsupportedCodec(codec).into()),
        };
        let mut attributes = Attributes::new();
        attributes.insert(AttrId::KeyData, key_bytes.into());
        Ok(Builder {
            codec,
            attributes: Some(attributes),
            ..Default::default()
        })
    }

    /// new builder from ssh_key::PublicKey source
    pub fn new_from_ssh_public_key(sshkey: &PublicKey) -> Result<Self, Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use EcdsaCurve::*;
                // SSH stores uncompressed SEC1 points; we store compressed internally
                let (key_bytes, codec) = match curve {
                    NistP256 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) = sshkey.key_data() {
                            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point.as_bytes())
                                .map_err(|e| {
                                ConversionsError::PublicKeyFailure(e.to_string())
                            })?;
                            (vk.to_sec1_bytes().to_vec(), Codec::P256Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP384 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP384(point)) = sshkey.key_data() {
                            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point.as_bytes())
                                .map_err(|e| {
                                ConversionsError::PublicKeyFailure(e.to_string())
                            })?;
                            (vk.to_sec1_bytes().to_vec(), Codec::P384Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP521 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP521(point)) = sshkey.key_data() {
                            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(point.as_bytes())
                                .map_err(|e| {
                                ConversionsError::PublicKeyFailure(e.to_string())
                            })?;
                            let ep = vk.as_affine().to_sec1_point(true);
                            (ep.as_bytes().to_vec(), Codec::P521Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            Other(name) => match name.as_str() {
                secp256k1::ALGORITHM_NAME => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Secp256K1Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let key_share = bls12381::KeyShare::try_from(key_bytes.as_ref())?;
                    let identifier: Vec<u8> = key_share.0 .0.to_be_bytes().into();
                    let threshold: Vec<u8> = Varuint(key_share.1).into();
                    let limit: Vec<u8> = Varuint(key_share.2).into();
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::ShareIdentifier, identifier.into());
                    attributes.insert(AttrId::Threshold, threshold.into());
                    attributes.insert(AttrId::Limit, limit.into());
                    attributes.insert(AttrId::KeyData, key_share.3.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1PubShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let key_share = bls12381::KeyShare::try_from(key_bytes.as_ref())?;
                    let identifier: Vec<u8> = key_share.0 .0.to_be_bytes().into();
                    let threshold: Vec<u8> = Varuint(key_share.1).into();
                    let limit: Vec<u8> = Varuint(key_share.2).into();
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::ShareIdentifier, identifier.into());
                    attributes.insert(AttrId::Threshold, threshold.into());
                    attributes.insert(AttrId::Limit, limit.into());
                    attributes.insert(AttrId::KeyData, key_share.3.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2PubShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                // ML-DSA public keys
                ml_dsa::ALGORITHM_NAME_65 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Mldsa65Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                ml_dsa::ALGORITHM_NAME_87 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Mldsa87Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                // FN-DSA public keys
                fn_dsa::ALGORITHM_NAME_512 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::FnDsa512Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                fn_dsa::ALGORITHM_NAME_1024 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::FnDsa1024Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                // SLH-DSA public keys
                slh_dsa::ALGORITHM_NAME_SHA2_128F => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2128FPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_128S => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2128SPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_192F => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2192FPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_192S => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2192SPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_256F => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2256FPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_256S => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2256SPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_128F => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake128FPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_128S => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake128SPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_192F => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake192FPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_192S => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake192SPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_256F => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake256FPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_256S => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake256SPub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                s => Err(ConversionsError::UnsupportedAlgorithm(s.to_string()).into()),
            },
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeyData::Ed25519(e) => e.0.to_vec(),
                    _ => {
                        return Err(ConversionsError::UnsupportedAlgorithm(
                            sshkey.algorithm().to_string(),
                        )
                        .into())
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec: Codec::Ed25519Pub,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            _ => Err(ConversionsError::UnsupportedAlgorithm(sshkey.algorithm().to_string()).into()),
        }
    }

    /// new builder from ssh_key::PrivateKey source
    pub fn new_from_ssh_private_key(sshkey: &PrivateKey) -> Result<Self, Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use EcdsaCurve::*;
                let (key_bytes, codec) = match curve {
                    NistP256 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice().to_vec(), Codec::P256Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP384 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice().to_vec(), Codec::P384Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP521 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP521 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice().to_vec(), Codec::P521Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            Other(name) => match name.as_str() {
                secp256k1::ALGORITHM_NAME => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Secp256K1Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G1_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let key_share = bls12381::KeyShare::try_from(key_bytes.as_ref())?;
                    let identifier: Vec<u8> = key_share.0 .0.to_be_bytes().into();
                    let threshold: Vec<u8> = Varuint(key_share.1).into();
                    let limit: Vec<u8> = Varuint(key_share.2).into();
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::ShareIdentifier, identifier.into());
                    attributes.insert(AttrId::Threshold, threshold.into());
                    attributes.insert(AttrId::Limit, limit.into());
                    attributes.insert(AttrId::KeyData, key_share.3.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1PrivShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                bls12381::ALGORITHM_NAME_G2_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let key_share = bls12381::KeyShare::try_from(key_bytes.as_ref())?;
                    let identifier: Vec<u8> = key_share.0 .0.to_be_bytes().into();
                    let threshold: Vec<u8> = Varuint(key_share.1).into();
                    let limit: Vec<u8> = Varuint(key_share.2).into();
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::ShareIdentifier, identifier.into());
                    attributes.insert(AttrId::Threshold, threshold.into());
                    attributes.insert(AttrId::Limit, limit.into());
                    attributes.insert(AttrId::KeyData, key_share.3.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2PrivShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                // ML-DSA private keys
                ml_dsa::ALGORITHM_NAME_65 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Mldsa65Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                ml_dsa::ALGORITHM_NAME_87 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Mldsa87Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                // FN-DSA private keys
                fn_dsa::ALGORITHM_NAME_512 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::FnDsa512Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                fn_dsa::ALGORITHM_NAME_1024 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::FnDsa1024Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                // SLH-DSA private keys
                slh_dsa::ALGORITHM_NAME_SHA2_128F => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2128FPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_128S => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2128SPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_192F => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2192FPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_192S => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2192SPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_256F => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2256FPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHA2_256S => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaSha2256SPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_128F => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake128FPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_128S => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake128SPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_192F => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake192FPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_192S => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake192SPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_256F => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake256FPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                slh_dsa::ALGORITHM_NAME_SHAKE_256S => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::SlhdsaShake256SPriv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        ..Default::default()
                    })
                }
                s => Err(ConversionsError::UnsupportedAlgorithm(s.to_string()).into()),
            },
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeypairData::Ed25519(e) => e.private.to_bytes().to_vec(),
                    _ => {
                        return Err(ConversionsError::UnsupportedAlgorithm(
                            sshkey.algorithm().to_string(),
                        )
                        .into())
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec: Codec::Ed25519Priv,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    ..Default::default()
                })
            }
            _ => Err(ConversionsError::UnsupportedAlgorithm(sshkey.algorithm().to_string()).into()),
        }
    }

    /// Create a new [Multikey] from a seed.
    ///
    /// Currently only supports [Codec::Ed25519Priv] seeds.
    pub fn new_from_seed(codec: Codec, seed: &[u8]) -> Result<Self, Error> {
        match codec {
            Codec::Ed25519Priv => {
                let keypair =
                    ssh_key::private::Ed25519Keypair::from_seed(seed.try_into().map_err(|_| {
                        ConversionsError::UnsupportedAlgorithm(
                            "Ed25519 seed must be 32 bytes long".to_string(),
                        )
                    })?);
                let private_key = PrivateKey::try_from(KeypairData::Ed25519(keypair))
                    .map_err(|e| ConversionsError::Ssh(e.into()))?;
                Self::new_from_ssh_private_key(&private_key)
            }
            _ => Err(ConversionsError::UnsupportedCodec(codec).into()),
        }
    }

    /// add an encoding
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// add a comment
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    fn with_attribute(mut self, attr: AttrId, data: &Vec<u8>) -> Self {
        let mut attributes = self.attributes.unwrap_or_default();
        attributes.insert(attr, data.to_owned().into());
        self.attributes = Some(attributes);
        self
    }

    /// add in the key bytes directly
    pub fn with_key_bytes(self, bytes: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::KeyData, &bytes.as_ref().to_vec())
    }

    /// add in the threshold value
    pub fn with_threshold(self, threshold: usize) -> Self {
        self.with_attribute(AttrId::Threshold, &Varuint(threshold).into())
    }

    /// add in the limit value
    pub fn with_limit(self, limit: usize) -> Self {
        self.with_attribute(AttrId::Limit, &Varuint(limit).into())
    }

    /// add in the share identifier value
    pub fn with_identifier(self, identifier: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::ShareIdentifier, &identifier.as_ref().to_vec())
    }

    /// add in the threshold data
    pub fn with_threshold_data(self, tdata: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::ThresholdData, &tdata.as_ref().to_vec())
    }

    /// Set the disclosure mode for a threshold share being built.
    ///
    /// In [`ThresholdDisclosure::Full`] mode, t and n are stored as plaintext
    /// attributes (same as `with_threshold()`/`with_limit()`).
    /// In [`ThresholdDisclosure::Partial`] mode, t is encrypted and n is plaintext.
    /// In [`ThresholdDisclosure::FullConfidentialial`] mode, both t and n are encrypted.
    ///
    /// `meta_key` is required for Partial/FullConfidentialial modes.
    pub fn with_disclosure(
        self,
        mode: threshold_meta::ThresholdDisclosure,
        meta_key: Option<&Multikey>,
        threshold: usize,
        limit: usize,
    ) -> Self {
        let mut attributes = self.attributes.unwrap_or_default();
        let _ = threshold_meta::stamp_disclosure_attrs(
            &mut attributes,
            mode,
            threshold,
            limit,
            meta_key,
        );
        Self {
            attributes: Some(attributes),
            ..self
        }
    }

    /// Stamp pre-encrypted threshold metadata directly (advanced use).
    ///
    /// This bypasses the encryption step — the caller has already encrypted the
    /// metadata and provides the ciphertext + cipher info directly.
    pub fn with_encrypted_threshold_meta(
        self,
        mode: threshold_meta::ThresholdDisclosure,
        encrypted_meta: Vec<u8>,
        cipher_info: threshold_meta::ThresholdMetaCipher,
        plaintext_limit: Option<usize>,
    ) -> Self {
        let mut attributes = self.attributes.unwrap_or_default();
        attributes.remove(&AttrId::Threshold);
        attributes.remove(&AttrId::Limit);
        attributes.remove(&AttrId::EncryptedThresholdMeta);
        attributes.remove(&AttrId::ThresholdMetaCipher);
        attributes.remove(&AttrId::ThresholdDisclosure);

        if let Some(n) = plaintext_limit {
            let n_bytes: Vec<u8> = Varuint(n).into();
            attributes.insert(AttrId::Limit, n_bytes.into());
        }
        attributes.insert(AttrId::EncryptedThresholdMeta, encrypted_meta.into());
        if let Ok(bytes) = cipher_info.to_cbor_bytes() {
            attributes.insert(AttrId::ThresholdMetaCipher, bytes.into());
        }
        attributes.insert(
            AttrId::ThresholdDisclosure,
            Zeroizing::new(threshold_meta::ThresholdDisclosure::encode_into(&mode)),
        );
        Self {
            attributes: Some(attributes),
            ..self
        }
    }

    /// add a key share
    pub fn add_key_share(mut self, share: &Multikey) -> Self {
        let mut shares = self.shares.unwrap_or_default();
        shares.push(share.clone());
        self.shares = Some(shares);
        self
    }

    /// build a base encoded multikey
    pub fn try_build_encoded(self) -> Result<EncodedMultikey, Error> {
        Ok(BaseEncoded::new(
            self.base_encoding
                .unwrap_or_else(Multikey::preferred_encoding),
            self.try_build()?,
        ))
    }

    /// build a key using key bytes
    pub fn try_build(self) -> Result<Multikey, Error> {
        let codec = self.codec;
        let comment = self.comment.unwrap_or_default();
        let attributes = self.attributes.unwrap_or_default();
        let mut mk = Multikey {
            codec,
            comment,
            attributes,
        };
        if let Some(shares) = self.shares {
            for share in &shares {
                mk = {
                    let tv = mk.threshold_view()?;
                    tv.add_share(share)?
                };
            }
            Ok(mk)
        } else {
            Ok(mk)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cipher, kdf};
    use multi_sig::EncodedMultisig;
    use ssh_key::private::Ed25519Keypair;

    #[test]
    fn test_random() {
        for codec in KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let (vpk, epk) = {
                let conv = mk.conv_view().unwrap();
                let pk = conv.to_public_key().unwrap();
                (Into::<Vec<u8>>::into(pk.clone()), EncodedMultikey::from(pk))
            };
            println!("encoded pubkey: {}: {}", codec, epk);
            println!("encoded pubkey v: {}: {}", codec, hex::encode(vpk));
            println!(
                "encoded privkey: {}: {}",
                codec,
                EncodedMultikey::from(mk.clone())
            );
            println!(
                "encoded privkey v: {}: {}",
                codec,
                hex::encode(Into::<Vec<u8>>::into(mk.clone()))
            );
            let _v: Vec<u8> = mk.into();
        }
    }

    #[test]
    fn test_encoded_random() {
        for codec in KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_base_encoding(Base::Base32Lower)
                .with_comment("test key")
                .try_build_encoded()
                .unwrap();
            let s = mk.to_string();
            //println!("encoded privkey: {}: {}", codec, s);
            assert_eq!(mk, EncodedMultikey::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_random_public_ssh_key_roundtrip() {
        for codec in KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let conv = mk.conv_view().unwrap();
            let pk = conv.to_public_key().unwrap();
            let ssh_key = conv.to_ssh_public_key().unwrap();
            let mk2 = Builder::new_from_ssh_public_key(&ssh_key)
                .unwrap()
                .try_build()
                .unwrap();
            assert_eq!(pk, mk2);
        }
    }

    #[test]
    fn test_random_private_ssh_key_roundtrip() {
        for codec in KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let conv = mk.conv_view().unwrap();
            let ssh_key = conv.to_ssh_private_key().unwrap();
            let mk2 = Builder::new_from_ssh_private_key(&ssh_key)
                .unwrap()
                .try_build()
                .unwrap();
            assert_eq!(mk, mk2);
        }
    }

    #[test]
    fn test_ssh_key_roundtrip() {
        for codec in KEY_CODECS {
            let mut rng = rand::rng();
            let sk1 = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let cv = sk1.conv_view().unwrap();
            let public_key = cv.to_ssh_public_key().unwrap();
            let private_key = cv.to_ssh_private_key().unwrap();

            let pk1 = cv.to_public_key().unwrap();
            let cv = pk1.conv_view().unwrap();
            assert_eq!(public_key, cv.to_ssh_public_key().unwrap());

            let sk2 = Builder::new_from_ssh_private_key(&private_key)
                .unwrap()
                .try_build()
                .unwrap();
            assert_eq!(sk1, sk2);
            let pk2 = Builder::new_from_ssh_public_key(&public_key)
                .unwrap()
                .try_build()
                .unwrap();
            assert_eq!(pk1, pk2);
        }
    }

    #[test]
    fn test_encryption_roundtrip() {
        for codec in KEY_CODECS {
            let mut rng = rand::rng();
            let mk1 = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();

            let attr = mk1.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk1.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());

            let mk2 = {
                let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                    .with_random_salt(bcrypt::SALT_LENGTH, &mut rng)
                    .with_rounds(10)
                    .try_build()
                    .unwrap();
                let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                    .with_random_nonce(chacha20::nonce_length(), &mut rng)
                    .try_build()
                    .unwrap();
                // get the kdf view on the cipher multikey so we can generate a
                // new cipher multikey with the same parameters and the generated key
                let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
                // derive a key from the passphrase and add it to the cipher multikey
                let ciphermk = kdf
                    .derive_key(b"for great justice, move every zig!")
                    .unwrap();
                // get the cipher view on the unencrypted ed25519 secret key so
                // that we can create a new ed25519 secret key with an encrypted
                // key and the kdf and cipher attributes and data
                let cipher = mk1.cipher_view(&ciphermk).unwrap();
                // encrypt the multikey using the cipher

                cipher.encrypt().unwrap()
            };

            let attr = mk2.attr_view().unwrap();
            assert!(attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk2.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_err()); // encrypted key

            let mk3 = {
                let kdfmk = kdf::Builder::default()
                    .try_from_multikey(&mk2)
                    .unwrap()
                    .try_build()
                    .unwrap();
                let ciphermk = cipher::Builder::default()
                    .try_from_multikey(&mk2)
                    .unwrap()
                    .try_build()
                    .unwrap();
                // get the kdf view
                let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
                // derive a key from the passphrase and add it to the cipher multikey
                let ciphermk = kdf
                    .derive_key(b"for great justice, move every zig!")
                    .unwrap();
                // get the cipher view
                let cipher = mk2.cipher_view(&ciphermk).unwrap();
                // decrypt the multikey using the cipher

                cipher.decrypt().unwrap()
            };

            let attr = mk3.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk3.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());

            // ensure the round trip worked
            assert_eq!(mk1, mk3);
        }
    }

    #[test]
    fn test_signing_detached_roundtrip() {
        for codec in KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();

            let attr = mk.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());
            let conv = mk.conv_view().unwrap();
            let pk = EncodedMultikey::new(Base::Base16Lower, conv.to_public_key().unwrap());
            println!("{} pubkey: {}", codec, pk);

            let msg = b"for great justice, move every zig!";

            let signmk = mk.sign_view().unwrap();
            let signature = if codec == Codec::Bls12381G1Priv || codec == Codec::Bls12381G2Priv {
                signmk.sign(msg.as_slice(), false, Some(2_u8)).unwrap()
            } else {
                signmk.sign(msg.as_slice(), false, None).unwrap()
            };
            let sig = EncodedMultisig::new(Base::Base16Lower, signature.clone());
            println!("signaure: {}", sig);

            let verifymk = mk.verify_view().unwrap();
            assert!(verifymk.verify(&signature, Some(msg.as_slice())).is_ok());
        }
    }

    #[test]
    fn test_signing_merged_roundtrip() {
        for codec in KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();

            let attr = mk.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());

            let msg =
                hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
                    .unwrap();

            let signmk = mk.sign_view().unwrap();
            let signature = if codec == Codec::Bls12381G1Priv || codec == Codec::Bls12381G2Priv {
                signmk.sign(&msg, true, Some(2_u8)).unwrap()
            } else {
                signmk.sign(&msg, true, None).unwrap()
            };

            // make sure the message is stored correctly in the signature
            assert_eq!(signature.message, msg);

            let verifymk = mk.verify_view().unwrap();
            assert!(verifymk.verify(&signature, None).is_ok());
        }
    }

    #[test]
    fn test_fn_dsa_random() {
        for codec in FN_DSA_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let (vpk, epk) = {
                let conv = mk.conv_view().unwrap();
                let pk = conv.to_public_key().unwrap();
                (Into::<Vec<u8>>::into(pk.clone()), EncodedMultikey::from(pk))
            };
            println!("encoded pubkey: {}: {}", codec, epk);
            println!("encoded pubkey v: {}: {}", codec, hex::encode(vpk));
            println!(
                "encoded privkey: {}: {}",
                codec,
                EncodedMultikey::from(mk.clone())
            );
            println!(
                "encoded privkey v: {}: {}",
                codec,
                hex::encode(Into::<Vec<u8>>::into(mk.clone()))
            );
            let _v: Vec<u8> = mk.into();
        }
    }

    #[test]
    fn test_fn_dsa_encoded_random() {
        for codec in FN_DSA_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_base_encoding(Base::Base32Lower)
                .with_comment("test key")
                .try_build_encoded()
                .unwrap();
            let s = mk.to_string();
            assert_eq!(mk, EncodedMultikey::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_fn_dsa_signing_detached_roundtrip() {
        for codec in FN_DSA_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();

            let attr = mk.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());
            let conv = mk.conv_view().unwrap();
            let pk = EncodedMultikey::new(Base::Base16Lower, conv.to_public_key().unwrap());
            println!("{} pubkey: {}", codec, pk);

            let msg = b"for great justice, move every zig!";

            let signmk = mk.sign_view().unwrap();
            let signature = signmk.sign(msg.as_slice(), false, None).unwrap();
            let sig = EncodedMultisig::new(Base::Base16Lower, signature.clone());
            println!("signature: {}", sig);

            let verifymk = mk.verify_view().unwrap();
            assert!(verifymk.verify(&signature, Some(msg.as_slice())).is_ok());
        }
    }

    #[test]
    fn test_fn_dsa_signing_merged_roundtrip() {
        for codec in FN_DSA_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();

            let attr = mk.attr_view().unwrap();
            assert!(!attr.is_encrypted());
            assert!(!attr.is_public_key());
            assert!(attr.is_secret_key());
            let kd = mk.data_view().unwrap();
            assert!(kd.key_bytes().is_ok());
            assert!(kd.secret_bytes().is_ok());

            let msg =
                hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
                    .unwrap();

            let signmk = mk.sign_view().unwrap();
            let signature = signmk.sign(&msg, true, None).unwrap();

            // make sure the message is stored correctly in the signature
            assert_eq!(signature.message, msg);

            let verifymk = mk.verify_view().unwrap();
            assert!(verifymk.verify(&signature, None).is_ok());
        }
    }

    #[test]
    fn test_ml_dsa_random() {
        for codec in ML_DSA_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let (vpk, epk) = {
                let conv = mk.conv_view().unwrap();
                let pk = conv.to_public_key().unwrap();
                (Into::<Vec<u8>>::into(pk.clone()), EncodedMultikey::from(pk))
            };
            println!("encoded pubkey: {}: {}", codec, epk);
            println!("encoded pubkey v: {}: {}", codec, hex::encode(vpk));
            println!(
                "encoded privkey: {}: {}",
                codec,
                EncodedMultikey::from(mk.clone())
            );
            println!(
                "encoded privkey v: {}: {}",
                codec,
                hex::encode(Into::<Vec<u8>>::into(mk.clone()))
            );
            let _v: Vec<u8> = mk.into();
        }
    }

    #[test]
    fn test_ml_dsa_encoded_random() {
        for codec in ML_DSA_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_base_encoding(Base::Base32Lower)
                .with_comment("test key")
                .try_build_encoded()
                .unwrap();
            let s = mk.to_string();
            assert_eq!(mk, EncodedMultikey::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_ml_dsa_signing_detached_roundtrip() {
        // ML-DSA signing allocates large key/signature buffers on the stack;
        // run on a 16 MiB stack to avoid overflowing the default test-thread
        // stack (matches `test_slh_dsa_signing_codec`).
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                for codec in ML_DSA_KEY_CODECS {
                    let mut rng = rand::rng();
                    let mk = Builder::new_from_random_bytes(codec, &mut rng)
                        .unwrap()
                        .with_comment("test key")
                        .try_build()
                        .unwrap();

                    let attr = mk.attr_view().unwrap();
                    assert!(!attr.is_encrypted());
                    assert!(!attr.is_public_key());
                    assert!(attr.is_secret_key());
                    let kd = mk.data_view().unwrap();
                    assert!(kd.key_bytes().is_ok());
                    assert!(kd.secret_bytes().is_ok());
                    let conv = mk.conv_view().unwrap();
                    let pk = EncodedMultikey::new(Base::Base16Lower, conv.to_public_key().unwrap());
                    println!("{} pubkey: {}", codec, pk);

                    let msg = b"for great justice, move every zig!";

                    let signmk = mk.sign_view().unwrap();
                    let signature = signmk.sign(msg.as_slice(), false, None).unwrap();
                    let sig = EncodedMultisig::new(Base::Base16Lower, signature.clone());
                    println!("signature: {}", sig);

                    let verifymk = mk.verify_view().unwrap();
                    assert!(verifymk.verify(&signature, Some(msg.as_slice())).is_ok());
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_ml_dsa_signing_merged_roundtrip() {
        // ML-DSA signing allocates large key/signature buffers on the stack;
        // run on a 16 MiB stack to avoid overflowing the default test-thread
        // stack (matches `test_slh_dsa_signing_codec`).
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                for codec in ML_DSA_KEY_CODECS {
                    let mut rng = rand::rng();
                    let mk = Builder::new_from_random_bytes(codec, &mut rng)
                        .unwrap()
                        .with_comment("test key")
                        .try_build()
                        .unwrap();

                    let attr = mk.attr_view().unwrap();
                    assert!(!attr.is_encrypted());
                    assert!(!attr.is_public_key());
                    assert!(attr.is_secret_key());
                    let kd = mk.data_view().unwrap();
                    assert!(kd.key_bytes().is_ok());
                    assert!(kd.secret_bytes().is_ok());

                    let msg = hex::decode(
                        "8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682",
                    )
                    .unwrap();

                    let signmk = mk.sign_view().unwrap();
                    let signature = signmk.sign(&msg, true, None).unwrap();

                    // make sure the message is stored correctly in the signature
                    assert_eq!(signature.message, msg);

                    let verifymk = mk.verify_view().unwrap();
                    assert!(verifymk.verify(&signature, None).is_ok());
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_slh_dsa_random() {
        for codec in SLH_DSA_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_comment("test key")
                .try_build()
                .unwrap();
            let (vpk, epk) = {
                let conv = mk.conv_view().unwrap();
                let pk = conv.to_public_key().unwrap();
                (Into::<Vec<u8>>::into(pk.clone()), EncodedMultikey::from(pk))
            };
            println!("encoded pubkey: {}: {}", codec, epk);
            println!("encoded pubkey v: {}: {}", codec, hex::encode(vpk));
            println!(
                "encoded privkey: {}: {}",
                codec,
                EncodedMultikey::from(mk.clone())
            );
            println!(
                "encoded privkey v: {}: {}",
                codec,
                hex::encode(Into::<Vec<u8>>::into(mk.clone()))
            );
            let _v: Vec<u8> = mk.into();
        }
    }

    #[test]
    fn test_slh_dsa_encoded_random() {
        for codec in SLH_DSA_KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .with_base_encoding(Base::Base32Lower)
                .with_comment("test key")
                .try_build_encoded()
                .unwrap();
            let s = mk.to_string();
            assert_eq!(mk, EncodedMultikey::try_from(s.as_str()).unwrap());
        }
    }

    #[test]
    fn test_slh_dsa_signing_detached_roundtrip() {
        // SLH-DSA signing uses large stack buffers internally (Merkle trees, WOTS+).
        // Spawn a thread with a larger stack to avoid overflow.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                for codec in SLH_DSA_KEY_CODECS {
                    let mut rng = rand::rng();
                    let mk = Builder::new_from_random_bytes(codec, &mut rng)
                        .unwrap()
                        .with_comment("test key")
                        .try_build()
                        .unwrap();

                    let attr = mk.attr_view().unwrap();
                    assert!(!attr.is_encrypted());
                    assert!(!attr.is_public_key());
                    assert!(attr.is_secret_key());
                    let kd = mk.data_view().unwrap();
                    assert!(kd.key_bytes().is_ok());
                    assert!(kd.secret_bytes().is_ok());
                    let conv = mk.conv_view().unwrap();
                    let pk = EncodedMultikey::new(Base::Base16Lower, conv.to_public_key().unwrap());
                    println!("{} pubkey: {}", codec, pk);

                    let msg = b"for great justice, move every zig!";

                    let signmk = mk.sign_view().unwrap();
                    let signature = signmk.sign(msg.as_slice(), false, None).unwrap();
                    let sig = EncodedMultisig::new(Base::Base16Lower, signature.clone());
                    println!("signature: {}", sig);

                    let verifymk = mk.verify_view().unwrap();
                    assert!(verifymk.verify(&signature, Some(msg.as_slice())).is_ok());
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_slh_dsa_signing_merged_roundtrip() {
        // SLH-DSA signing uses large stack buffers internally (Merkle trees, WOTS+).
        // Spawn a thread with a larger stack to avoid overflow.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                for codec in SLH_DSA_KEY_CODECS {
                    let mut rng = rand::rng();
                    let mk = Builder::new_from_random_bytes(codec, &mut rng)
                        .unwrap()
                        .with_comment("test key")
                        .try_build()
                        .unwrap();

                    let attr = mk.attr_view().unwrap();
                    assert!(!attr.is_encrypted());
                    assert!(!attr.is_public_key());
                    assert!(attr.is_secret_key());
                    let kd = mk.data_view().unwrap();
                    assert!(kd.key_bytes().is_ok());
                    assert!(kd.secret_bytes().is_ok());

                    let msg = hex::decode(
                        "8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682",
                    )
                    .unwrap();

                    let signmk = mk.sign_view().unwrap();
                    let signature = signmk.sign(&msg, true, None).unwrap();

                    // make sure the message is stored correctly in the signature
                    assert_eq!(signature.message, msg);

                    let verifymk = mk.verify_view().unwrap();
                    assert!(verifymk.verify(&signature, None).is_ok());
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_bls_key_combine() {
        let mut rng = rand::rng();
        let mk1 = Builder::new_from_random_bytes(Codec::Bls12381G1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        assert_eq!("test key".to_string(), mk1.comment);

        let tv = mk1.threshold_view().unwrap();
        let shares = tv.split(3, 4).unwrap();
        assert_eq!(4, shares.len());
        for share in &shares {
            assert_eq!("test key".to_string(), share.comment);
        }

        let msg = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();

        let signmk = shares[0].sign_view().unwrap();
        let signature = signmk.sign(msg.as_slice(), false, Some(2_u8)).unwrap();
        let ms: EncodedMultisig = BaseEncoded::new(Base::Base32Z, signature);
        let s = ms.to_string();
        println!("Bls Sig Share: {}", s);

        let mut builder = Builder::new(Codec::Bls12381G1Priv).with_comment("test key");
        for share in &shares {
            builder = builder.add_key_share(share);
        }
        let mk2 = builder.try_build().unwrap();
        assert_eq!("test key".to_string(), mk2.comment);

        let av = mk2.threshold_attr_view().unwrap();
        assert_eq!(3, av.threshold().unwrap());
        assert_eq!(4, av.limit().unwrap());

        let tv = mk2.threshold_view().unwrap();
        let mk3 = tv.combine().unwrap();
        assert_eq!("test key".to_string(), mk3.comment);

        assert_eq!(mk1, mk3);
    }

    #[test]
    fn test_bls_share_ssh_key_roundtrip() {
        let mut rng = rand::rng();
        let mk = Builder::new_from_random_bytes(Codec::Bls12381G1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let tv = mk.threshold_view().unwrap();
        let sk1 = { tv.split(3, 4).unwrap()[0].clone() };

        assert_eq!(Codec::Bls12381G1PrivShare, sk1.codec);
        let cv = sk1.conv_view().unwrap();
        let public_key = cv.to_ssh_public_key().unwrap();
        let private_key = cv.to_ssh_private_key().unwrap();

        let pk1 = cv.to_public_key().unwrap();
        let cv = pk1.conv_view().unwrap();
        assert_eq!(public_key, cv.to_ssh_public_key().unwrap());

        let sk2 = Builder::new_from_ssh_private_key(&private_key)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(sk1, sk2);
        let pk2 = Builder::new_from_ssh_public_key(&public_key)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_from_ssh_pubkey() {
        let mut rng = rand::rng();
        let kp = KeypairData::Ed25519(Ed25519Keypair::random(&mut rng));
        let sk = PrivateKey::new(kp, "test key").unwrap();

        // build a multikey from the public key
        let mk = Builder::new_from_ssh_public_key(sk.public_key())
            .unwrap()
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(attr.is_public_key());
        assert!(!attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // public key
    }

    #[test]
    fn test_from_ssh_privkey() {
        let mut rng = rand::rng();
        let kp = KeypairData::Ed25519(Ed25519Keypair::random(&mut rng));
        let sk = PrivateKey::new(kp, "test key").unwrap();

        let mk = Builder::new_from_ssh_private_key(&sk)
            .unwrap()
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }

    #[test]
    fn test_pub_from_string() {
        let s = "fba24ed010874657374206b6579010120f9ddcd5118319cc69e6985ef3f4ee3b6c591d46255e1ae5569c8662111b7d3c2".to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Pub);
        assert_eq!(mk.encoding(), Base::Base16Lower);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(attr.is_public_key());
        assert!(!attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // public key
    }

    #[test]
    fn test_priv_from_string() {
        let s = "fba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04".to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.encoding(), Base::Base16Lower);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }

    #[test]
    fn test_pub_from_vec() {
        let b = hex::decode("ba24ed010874657374206b6579010120f9ddcd5118319cc69e6985ef3f4ee3b6c591d46255e1ae5569c8662111b7d3c2").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(attr.is_public_key());
        assert!(!attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // public key
    }

    #[test]
    fn test_priv_from_vec() {
        let b = hex::decode("ba2480260874657374206b657901012064e58adf88f85cbec6a0448a0803f9d28cf9231a7141be413f83cf6aa883cd04").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }

    #[test]
    fn test_null() {
        let mk1 = Multikey::null();
        assert!(mk1.is_null());
        let mk2 = Multikey::default();
        assert_eq!(mk1, mk2);
        assert!(mk2.is_null());
    }

    #[test]
    fn test_from_seed() {
        let seed = hex::decode("f9ddcd5118319cc69e6985ef3f4ee3b6c591d46255e1ae5569c8662111b7d3c2")
            .unwrap();
        let mk = Builder::new_from_seed(Codec::Ed25519Priv, seed.as_slice())
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }
}
