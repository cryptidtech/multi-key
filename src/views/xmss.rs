// SPDX-License-Identifier: Apache-2.0
//! XMSS-SHA2_10/16/20_256 stateful hash-based signature multikey view; RFC 8391.
#![allow(dead_code)]
//!
//! XMSS is stateful: every signature consumes a one-time leaf `index` that must
//! never be reused. [`SignView::sign`] embeds the consumed index in the returned
//! [`Multisig`] as [`multi_sig::AttrId::SigIndex`], so the index travels with
//! the signature (e.g. into a provenance log, where monotonicity is enforced).
//!
//! NOTE: this view signs at whatever index the stored secret key currently holds;
//! it does NOT persist the advanced secret key. The authoritative advance-and-
//! persist is owned by the keystore (`bs-keystore`), which calls [`sign_advance`]
//! to obtain both the signature and the advanced secret key in one step.

use crate::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView,
    error::{AttributesError, ConversionsError, SignError, VerifyError},
    views::Views,
};
use multi_codec::Codec;
use multi_hash::{Multihash, mh};
use multi_sig::{Views as _, ms};
use zeroize::Zeroizing;

// ---- Inlined bs-xmss wrapper logic ----

mod xmss_wrapper {
    use super::Zeroizing;
    use xmss::{
        DetachedSignature, KeyPair, SigningKey, VerifyingKey, XmssParameter, XmssSha2_10_256,
        XmssSha2_16_256, XmssSha2_20_256,
    };

    const XMSS_OID_LEN: usize = 4;
    const XMSS_INDEX_LEN: usize = 4;

    pub struct XmssSignature {
        pub signature: Vec<u8>,
        pub index: u32,
        pub advanced_secret_key: Zeroizing<Vec<u8>>,
    }

    pub fn current_index(secret_key_bytes: &[u8]) -> Result<u32, String> {
        let end = XMSS_OID_LEN + XMSS_INDEX_LEN;
        if secret_key_bytes.len() < end {
            return Err("xmss secret key too short for index".to_string());
        }
        let mut idx = [0u8; XMSS_INDEX_LEN];
        idx.copy_from_slice(&secret_key_bytes[XMSS_OID_LEN..end]);
        Ok(u32::from_be_bytes(idx))
    }

    fn keypair<P: XmssParameter>() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
        let mut kp = KeyPair::<P>::generate(&mut rand::rng()).map_err(|e| e.to_string())?;
        let pk = kp.verifying_key().as_ref().to_vec();
        let sk = Zeroizing::new(kp.signing_key().as_ref().to_vec());
        Ok((pk, sk))
    }

    fn sign<P: XmssParameter>(
        secret_key_bytes: &[u8],
        msg: &[u8],
    ) -> Result<XmssSignature, String> {
        let index = current_index(secret_key_bytes)?;
        let mut sk = SigningKey::<P>::try_from(secret_key_bytes).map_err(|e| e.to_string())?;
        let sig = sk.sign_detached(msg).map_err(|e| e.to_string())?;
        Ok(XmssSignature {
            signature: sig.as_ref().to_vec(),
            index,
            advanced_secret_key: Zeroizing::new(sk.as_ref().to_vec()),
        })
    }

    fn verify<P: XmssParameter>(
        public_key_bytes: &[u8],
        signature_bytes: &[u8],
        msg: &[u8],
    ) -> Result<(), String> {
        let vk = VerifyingKey::<P>::try_from(public_key_bytes).map_err(|e| e.to_string())?;
        let sig = DetachedSignature::<P>::try_from(signature_bytes).map_err(|e| e.to_string())?;
        vk.verify_detached(&sig, msg).map_err(|e| e.to_string())
    }

    fn public_from_private<P: XmssParameter>(secret_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let sk = SigningKey::<P>::try_from(secret_key_bytes).map_err(|e| e.to_string())?;
        Ok(VerifyingKey::<P>::from(&sk).as_ref().to_vec())
    }

    macro_rules! param_api {
        ($param:ty, $kp:ident, $sign:ident, $verify:ident, $pfp:ident) => {
            pub fn $kp() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), String> {
                keypair::<$param>()
            }
            pub fn $sign(s: &[u8], m: &[u8]) -> Result<XmssSignature, String> {
                sign::<$param>(s, m)
            }
            pub fn $verify(p: &[u8], s: &[u8], m: &[u8]) -> Result<(), String> {
                verify::<$param>(p, s, m)
            }
            pub fn $pfp(s: &[u8]) -> Result<Vec<u8>, String> {
                public_from_private::<$param>(s)
            }
        };
    }

    param_api!(
        XmssSha2_10_256,
        keypair_10,
        sign_10,
        verify_10,
        public_from_private_10
    );
    param_api!(
        XmssSha2_16_256,
        keypair_16,
        sign_16,
        verify_16,
        public_from_private_16
    );
    param_api!(
        XmssSha2_20_256,
        keypair_20,
        sign_20,
        verify_20,
        public_from_private_20
    );
}

fn is_xmss_priv(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::XmssSha210256Priv | Codec::XmssSha216256Priv | Codec::XmssSha220256Priv
    )
}

fn is_xmss_pub(codec: Codec) -> bool {
    matches!(
        codec,
        Codec::XmssSha210256Pub | Codec::XmssSha216256Pub | Codec::XmssSha220256Pub
    )
}

fn public_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::XmssSha210256Priv => Ok(Codec::XmssSha210256Pub),
        Codec::XmssSha216256Priv => Ok(Codec::XmssSha216256Pub),
        Codec::XmssSha220256Priv => Ok(Codec::XmssSha220256Pub),
        _ => Err(ConversionsError::SecretKeyFailure("not an XMSS private key".into()).into()),
    }
}

fn msig_codec(codec: Codec) -> Result<Codec, Error> {
    match codec {
        Codec::XmssSha210256Priv => Ok(Codec::XmssSha210256Msig),
        Codec::XmssSha216256Priv => Ok(Codec::XmssSha216256Msig),
        Codec::XmssSha220256Priv => Ok(Codec::XmssSha220256Msig),
        _ => Err(SignError::NotSigningKey.into()),
    }
}

fn public_from_private(codec: Codec, secret_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    match codec {
        Codec::XmssSha210256Priv => xmss_wrapper::public_from_private_10(secret_bytes),
        Codec::XmssSha216256Priv => xmss_wrapper::public_from_private_16(secret_bytes),
        Codec::XmssSha220256Priv => xmss_wrapper::public_from_private_20(secret_bytes),
        _ => {
            return Err(
                ConversionsError::SecretKeyFailure("not an XMSS private key".into()).into(),
            );
        }
    }
    .map_err(|e| ConversionsError::SecretKeyFailure(e).into())
}

fn keypair(codec: Codec) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    match codec {
        Codec::XmssSha210256Priv => xmss_wrapper::keypair_10(),
        Codec::XmssSha216256Priv => xmss_wrapper::keypair_16(),
        Codec::XmssSha220256Priv => xmss_wrapper::keypair_20(),
        _ => {
            return Err(
                ConversionsError::SecretKeyFailure("not an XMSS private key".into()).into(),
            );
        }
    }
    .map_err(|e| ConversionsError::SecretKeyFailure(e).into())
}

fn sign_bytes(
    codec: Codec,
    secret_bytes: &[u8],
    msg: &[u8],
) -> Result<xmss_wrapper::XmssSignature, Error> {
    match codec {
        Codec::XmssSha210256Priv => xmss_wrapper::sign_10(secret_bytes, msg),
        Codec::XmssSha216256Priv => xmss_wrapper::sign_16(secret_bytes, msg),
        Codec::XmssSha220256Priv => xmss_wrapper::sign_20(secret_bytes, msg),
        _ => return Err(SignError::NotSigningKey.into()),
    }
    .map_err(|e| SignError::SigningFailed(e).into())
}

fn verify_bytes(codec: Codec, pub_bytes: &[u8], sig_bytes: &[u8], msg: &[u8]) -> Result<(), Error> {
    match codec {
        Codec::XmssSha210256Pub => xmss_wrapper::verify_10(pub_bytes, sig_bytes, msg),
        Codec::XmssSha216256Pub => xmss_wrapper::verify_16(pub_bytes, sig_bytes, msg),
        Codec::XmssSha220256Pub => xmss_wrapper::verify_20(pub_bytes, sig_bytes, msg),
        _ => return Err(VerifyError::BadSignature("not an XMSS public key".into()).into()),
    }
    .map_err(|e| VerifyError::BadSignature(e).into())
}

/// Build a [`Multisig`](multi_sig::Multisig) from a computed XMSS signature,
/// embedding the consumed leaf index as [`AttrId::SigIndex`](multi_sig::AttrId::SigIndex).
fn build_multisig(
    priv_codec: Codec,
    sig: &xmss_wrapper::XmssSignature,
    msg: &[u8],
    combined: bool,
) -> Result<multi_sig::Multisig, Error> {
    let mut ms = ms::Builder::new(msig_codec(priv_codec)?)
        .with_signature_bytes(&sig.signature)
        .with_sig_index(sig.index);
    if combined {
        ms = ms.with_message_bytes(&msg);
    }
    Ok(ms.try_build()?)
}

/// Sign `msg`, returning the [`Multisig`](multi_sig::Multisig) AND the advanced
/// secret key bytes. The caller (keystore) MUST persist the advanced key so the
/// consumed leaf index is never reused.
///
/// Returns an error if the multikey is not an XMSS secret key.
pub fn sign_advance(
    mk: &Multikey,
    msg: &[u8],
    combined: bool,
) -> Result<(multi_sig::Multisig, Zeroizing<Vec<u8>>), Error> {
    let attr = mk.attr_view()?;
    if !attr.is_secret_key() || !is_xmss_priv(mk.codec) {
        return Err(SignError::NotSigningKey.into());
    }
    let secret_bytes = {
        let kd = mk.data_view()?;
        kd.secret_bytes()?
    };
    let sig = sign_bytes(mk.codec, secret_bytes.as_slice(), msg)?;
    let ms = build_multisig(mk.codec, &sig, msg, combined)?;
    Ok((ms, sig.advanced_secret_key.clone()))
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
        is_xmss_priv(self.mk.codec)
    }
    fn is_public_key(&self) -> bool {
        is_xmss_pub(self.mk.codec)
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
        Err(
            ConversionsError::UnsupportedAlgorithm("XMSS not supported in SSH key format".into())
                .into(),
        )
    }
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        Err(
            ConversionsError::UnsupportedAlgorithm("XMSS not supported in SSH key format".into())
                .into(),
        )
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
    fn sign(
        &self,
        msg: &[u8],
        combined: bool,
        _scheme: Option<u8>,
    ) -> Result<multi_sig::Multisig, Error> {
        let attr = self.mk.attr_view()?;
        if !attr.is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }
        let secret_bytes = {
            let kd = self.mk.data_view()?;
            kd.secret_bytes()?
        };
        let sig = sign_bytes(self.mk.codec, secret_bytes.as_slice(), msg)?;
        build_multisig(self.mk.codec, &sig, msg, combined)
    }
}

impl<'a> VerifyView for View<'a> {
    fn verify(&self, sig: &multi_sig::Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let msg_bytes = if let Some(m) = msg {
            m
        } else if !sig.message.is_empty() {
            sig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        let attr = self.mk.attr_view()?;
        let pubmk = if attr.is_secret_key() {
            let kc = self.mk.conv_view()?;
            kc.to_public_key()?
        } else {
            self.mk.clone()
        };

        let key_bytes = {
            let kd = pubmk.data_view()?;
            kd.key_bytes()?
        };
        let sv = sig.data_view()?;
        let sig_bytes = sv.sig_bytes()?;

        verify_bytes(pubmk.codec, key_bytes.as_slice(), &sig_bytes, msg_bytes)
    }
}

pub(crate) fn generate_private_key(codec: Codec) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (_pk, sk) = keypair(codec)?;
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Builder;

    #[test]
    fn test_xmss_sign_verify_and_index() {
        // Only h=10 is exercised: h=16/20 keygen builds a 2^h Merkle tree (minutes).
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::XmssSha210256Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();

        let msg = b"provenance entry bytes";
        let ms = sk.sign_view().unwrap().sign(msg, false, None).unwrap();
        // the consumed leaf index (0) travels with the signature
        assert_eq!(ms.sig_index(), Some(0));

        // verify with the public key and with the secret key's derived public key
        pk.verify_view().unwrap().verify(&ms, Some(msg)).unwrap();
        sk.verify_view().unwrap().verify(&ms, Some(msg)).unwrap();

        // wrong message must fail
        assert!(
            pk.verify_view()
                .unwrap()
                .verify(&ms, Some(b"tampered"))
                .is_err()
        );
    }

    #[test]
    fn test_xmss_sign_advance_persists_index() {
        let mut rng = rand::rng();
        let sk = Builder::new_from_random_bytes(Codec::XmssSha210256Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();

        let (ms0, advanced) = sign_advance(&sk, b"first", false).unwrap();
        assert_eq!(ms0.sig_index(), Some(0));
        // advanced secret key now points at index 1
        assert_eq!(xmss_wrapper::current_index(&advanced).unwrap(), 1);
    }
}
