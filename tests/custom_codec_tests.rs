// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for custom protocol keys (sigil-0, the
//! `Codec::Identity` codec carrying `AlgorithmName` and `KeyType`
//! attributes): public construction through the `Builder` attribute
//! setters, wire and serde roundtrips, and `ViewBuilder` local-codec
//! factory dispatch including the `AlgorithmName` disambiguation
//! convention for keys that share a codec.

use multi_codec::Codec;
use multi_hash::{Multihash, mh};
use multi_key::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, FingerprintView, Multikey, SignView,
    VerifyView, ViewBuilder,
};
use multi_sig::Multisig;
use multi_trait::Null;
use multi_util::CodecInfo;
use ssh_key::{PrivateKey, PublicKey};
use zeroize::Zeroizing;

/// The raw `KeyType` attribute byte of `mk`, or 0 (public) when the
/// attribute is absent or empty, per the byte convention from
/// provenance-specifications#4.
fn key_type_byte(mk: &Multikey) -> u8 {
    mk.attributes
        .get(&AttrId::KeyType)
        .and_then(|t| t.first().copied())
        .unwrap_or(0)
}

/// The `AlgorithmName` attribute value of `mk`, or an error if the
/// attribute is missing or not UTF-8.
fn algorithm_name(mk: &Multikey) -> Result<&str, Error> {
    let bytes = mk
        .attributes
        .get(&AttrId::AlgorithmName)
        .ok_or_else(|| Error::UnsupportedAlgorithm("AlgorithmName missing".into()))?;
    std::str::from_utf8(bytes)
        .map_err(|_| Error::UnsupportedAlgorithm("AlgorithmName not UTF-8".into()))
}

/// An attributes view over a custom key, reporting the key type byte
/// convention: absent or 0 means public, 1 means secret.
struct CustomAttrs {
    key_type: u8,
}

impl AttrView for CustomAttrs {
    fn is_encrypted(&self) -> bool {
        false
    }

    fn is_public_key(&self) -> bool {
        self.key_type == 0
    }

    fn is_secret_key(&self) -> bool {
        self.key_type == 1
    }

    fn is_secret_key_share(&self) -> bool {
        false
    }
}

/// A view over the key data of a custom key.
struct CustomData {
    key_bytes: Vec<u8>,
}

impl DataView for CustomData {
    fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        Ok(Zeroizing::new(self.key_bytes.clone()))
    }

    fn secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        Ok(Zeroizing::new(self.key_bytes.clone()))
    }
}

/// A conversion view over a custom key. Per the byte convention from
/// provenance-specifications#4, a secret (key type 1) custom key converts
/// to its public form by storing key type 0.
struct CustomConv {
    key_type: u8,
    key: Multikey,
}

impl ConvView for CustomConv {
    fn to_public_key(&self) -> Result<Multikey, Error> {
        if self.key_type != 1 {
            return Err(Error::UnsupportedAlgorithm(
                "custom public key has no public form".into(),
            ));
        }
        let mut pk = self.key.clone();
        pk.attributes
            .insert(AttrId::KeyType, Zeroizing::new(vec![0]));
        Ok(pk)
    }

    fn to_ssh_public_key(&self) -> Result<PublicKey, Error> {
        Err(Error::UnsupportedAlgorithm(
            "custom keys have no ssh form".into(),
        ))
    }

    fn to_ssh_private_key(&self) -> Result<PrivateKey, Error> {
        Err(Error::UnsupportedAlgorithm(
            "custom keys have no ssh form".into(),
        ))
    }
}

/// A fingerprint view over a custom key: the hash of the key data bytes.
struct CustomFingerprint {
    key_bytes: Vec<u8>,
}

impl FingerprintView for CustomFingerprint {
    fn fingerprint(&self, hash: Codec) -> Result<Multihash, Error> {
        let mut b = mh::Builder::new(hash)?;
        b.update(&self.key_bytes);
        b.output_len(32);
        Ok(b.try_build()?)
    }
}

/// A signing view that reports the protocol it serves through its error,
/// so tests can assert which factory produced the view.
struct NamedSign {
    name: &'static str,
}

impl SignView for NamedSign {
    fn sign(&self, _: &[u8], _: bool, _: Option<u8>) -> Result<Multisig, Error> {
        Err(Error::UnsupportedAlgorithm(format!("{} sign", self.name)))
    }
}

/// A verification view that reports the protocol it serves through its
/// error, so tests can assert which factory produced the view.
struct NamedVerify {
    name: String,
}

impl VerifyView for NamedVerify {
    fn verify(&self, _: &Multisig, _: Option<&[u8]>) -> Result<(), Error> {
        Err(Error::UnsupportedAlgorithm(format!("{} verify", self.name)))
    }
}

/// A factory for the basic-attributes view kind. It serves the key's
/// protocol, which it identifies through the `AlgorithmName` attribute.
fn attr_factory<'a>(mk: &'a Multikey) -> Result<Box<dyn AttrView + 'a>, Error> {
    algorithm_name(mk)?;
    Ok(Box::new(CustomAttrs {
        key_type: key_type_byte(mk),
    }))
}

/// A factory for the key-data view kind.
fn data_factory<'a>(mk: &'a Multikey) -> Result<Box<dyn DataView + 'a>, Error> {
    let key_bytes = mk
        .attributes
        .get(&AttrId::KeyData)
        .ok_or_else(|| Error::UnsupportedAlgorithm("KeyData missing".into()))?
        .to_vec();
    Ok(Box::new(CustomData { key_bytes }))
}

/// A factory for the key-conversion view kind. It serves the key's
/// protocol, which it identifies through the `AlgorithmName` attribute.
fn conv_factory<'a>(mk: &'a Multikey) -> Result<Box<dyn ConvView + 'a>, Error> {
    algorithm_name(mk)?;
    Ok(Box::new(CustomConv {
        key_type: key_type_byte(mk),
        key: mk.clone(),
    }))
}

/// A factory for the fingerprint view kind.
fn fingerprint_factory<'a>(mk: &'a Multikey) -> Result<Box<dyn FingerprintView + 'a>, Error> {
    let key_bytes = mk
        .attributes
        .get(&AttrId::KeyData)
        .ok_or_else(|| Error::UnsupportedAlgorithm("KeyData missing".into()))?
        .to_vec();
    Ok(Box::new(CustomFingerprint { key_bytes }))
}

/// A factory for the verification view kind, named after the key's
/// `AlgorithmName`.
fn verify_factory<'a>(mk: &'a Multikey) -> Result<Box<dyn VerifyView + 'a>, Error> {
    Ok(Box::new(NamedVerify {
        name: algorithm_name(mk)?.to_string(),
    }))
}

/// A factory for the signing view kind that serves only the `serves`
/// protocol: keys sharing `Codec::Identity` are disambiguated by their
/// `AlgorithmName` attribute, not by the codec.
fn sign_factory(
    serves: &'static str,
) -> impl for<'a> Fn(&'a Multikey) -> Result<Box<dyn SignView + 'a>, Error> + Send + Sync + 'static
{
    move |mk| {
        if algorithm_name(mk)? == serves {
            Ok(Box::new(NamedSign { name: serves }))
        } else {
            Err(Error::UnsupportedAlgorithm(format!(
                "this factory serves {serves} only"
            )))
        }
    }
}

/// Build a custom protocol key through the public `Builder` setters and
/// decode it back from its wire encoding, so tests exercise the decoded
/// form the way custom keys usually arrive.
fn decoded_custom_key(name: &str, key_type: u8) -> Multikey {
    let built = Builder::new(Codec::Identity)
        .with_comment("custom protocol key")
        .with_key_bytes(b"custom-key-seed".as_slice())
        .with_algorithm_name(name)
        .with_key_type(key_type)
        .try_build()
        .unwrap();
    let bytes: Vec<u8> = built.into();
    Multikey::try_from(bytes.as_ref()).unwrap()
}

/// Test that the setters stamp the `AlgorithmName` (code 27) and `KeyType`
/// (code 28) attributes on the built key.
#[test]
fn test_custom_key_builder_stamps_attributes() {
    let built = Builder::new(Codec::Identity)
        .with_key_bytes(b"custom-key-seed".as_slice())
        .with_algorithm_name("my-protocol")
        .with_key_type(1)
        .try_build()
        .unwrap();
    assert_eq!(built.codec(), Codec::Identity);
    assert_eq!(
        built
            .attributes
            .get(&AttrId::AlgorithmName)
            .unwrap()
            .as_slice(),
        b"my-protocol".as_slice()
    );
    assert_eq!(
        built.attributes.get(&AttrId::KeyType).unwrap().as_slice(),
        b"\x01".as_slice()
    );
}

/// Test that a custom key built through the public setters roundtrips
/// through the wire encoding unchanged.
#[test]
fn test_custom_key_wire_roundtrip() {
    let built = Builder::new(Codec::Identity)
        .with_comment("custom protocol key")
        .with_key_bytes(b"custom-key-seed".as_slice())
        .with_algorithm_name("my-protocol")
        .with_key_type(1)
        .try_build()
        .unwrap();
    let bytes: Vec<u8> = built.clone().into();
    let decoded = Multikey::try_from(bytes.as_ref()).unwrap();
    assert_eq!(decoded, built);
    assert_eq!(decoded.codec(), Codec::Identity);
    assert_eq!(
        decoded
            .attributes
            .get(&AttrId::AlgorithmName)
            .unwrap()
            .as_slice(),
        b"my-protocol".as_slice()
    );
    assert_eq!(
        decoded.attributes.get(&AttrId::KeyType).unwrap().as_slice(),
        b"\x01".as_slice()
    );
}

/// Test that the empty algorithm-name string is accepted and stored
/// unvalidated, and survives the wire roundtrip.
#[test]
fn test_empty_algorithm_name_is_accepted() {
    let built = Builder::new(Codec::Identity)
        .with_key_bytes(b"custom-key-seed".as_slice())
        .with_algorithm_name("")
        .with_key_type(0)
        .try_build()
        .unwrap();
    assert_eq!(
        built
            .attributes
            .get(&AttrId::AlgorithmName)
            .unwrap()
            .as_slice(),
        b"".as_slice()
    );
    let bytes: Vec<u8> = built.into();
    let decoded = Multikey::try_from(bytes.as_ref()).unwrap();
    assert_eq!(
        decoded
            .attributes
            .get(&AttrId::AlgorithmName)
            .unwrap()
            .as_slice(),
        b"".as_slice()
    );
}

/// Test that custom-key views build through the `ViewBuilder` with a
/// registered local factory per kind: attr, data, conv, and fingerprint.
#[test]
fn test_custom_key_factory_dispatch() {
    let mk = decoded_custom_key("my-protocol", 1);

    // the attributes view reports the key type byte convention
    let attrs = ViewBuilder::new(&mk)
        .attr()
        .with_local_codec(Codec::Identity, attr_factory)
        .build()
        .unwrap();
    assert!(attrs.is_secret_key());
    assert!(!attrs.is_public_key());
    assert!(!attrs.is_encrypted());
    assert!(!attrs.is_secret_key_share());

    // the same factory reports public for a key type 0 custom key
    let public = decoded_custom_key("my-protocol", 0);
    let attrs = ViewBuilder::new(&public)
        .attr()
        .with_local_codec(Codec::Identity, attr_factory)
        .build()
        .unwrap();
    assert!(attrs.is_public_key());
    assert!(!attrs.is_secret_key());

    // the key-data view returns the key bytes
    let data = ViewBuilder::new(&mk)
        .data()
        .with_local_codec(Codec::Identity, data_factory)
        .build()
        .unwrap();
    assert_eq!(
        data.key_bytes().unwrap().as_slice(),
        b"custom-key-seed".as_slice()
    );

    // a secret (key type 1) custom key converts to a public key storing
    // key type 0
    let conv = ViewBuilder::new(&mk)
        .conv()
        .with_local_codec(Codec::Identity, conv_factory)
        .build()
        .unwrap();
    let public_key = conv.to_public_key().unwrap();
    assert_eq!(
        public_key
            .attributes
            .get(&AttrId::KeyType)
            .unwrap()
            .as_slice(),
        b"\x00".as_slice()
    );
    assert_eq!(
        conv.to_ssh_public_key().err().unwrap().to_string(),
        "Unsupported key algorithm: custom keys have no ssh form"
    );

    // the fingerprint view hashes the key data bytes
    let fp = ViewBuilder::new(&mk)
        .fingerprint()
        .with_local_codec(Codec::Identity, fingerprint_factory)
        .build()
        .unwrap();
    let mut b = mh::Builder::new(Codec::Blake2S256).unwrap();
    b.update(b"custom-key-seed".as_slice());
    b.output_len(32);
    let expected = b.try_build().unwrap();
    assert_eq!(fp.fingerprint(Codec::Blake2S256).unwrap(), expected);
}

/// Test that two custom keys sharing the `Codec::Identity` codec but
/// carrying different `AlgorithmName` values each reach the factory that
/// serves their protocol through caller-side branching.
#[test]
fn test_algorithm_name_branching() {
    let alpha = decoded_custom_key("alpha-protocol", 1);
    let beta = decoded_custom_key("beta-protocol", 1);

    // each key reaches the factory serving its protocol
    let sign = ViewBuilder::new(&alpha)
        .sign()
        .with_local_codec(Codec::Identity, sign_factory("alpha-protocol"))
        .build()
        .unwrap();
    assert_eq!(
        sign.sign(b"message", false, None)
            .err()
            .unwrap()
            .to_string(),
        "Unsupported key algorithm: alpha-protocol sign"
    );

    let sign = ViewBuilder::new(&beta)
        .sign()
        .with_local_codec(Codec::Identity, sign_factory("beta-protocol"))
        .build()
        .unwrap();
    assert_eq!(
        sign.sign(b"message", false, None)
            .err()
            .unwrap()
            .to_string(),
        "Unsupported key algorithm: beta-protocol sign"
    );

    // the factory serving alpha rejects beta's key: the built-in dispatch
    // never supports a custom codec, so the factory's error propagates
    let err = ViewBuilder::new(&beta)
        .sign()
        .with_local_codec(Codec::Identity, sign_factory("alpha-protocol"))
        .build()
        .err()
        .unwrap();
    assert_eq!(
        err.to_string(),
        "Unsupported key algorithm: this factory serves alpha-protocol only"
    );

    // the same branching works over the verification view kind
    let verify = ViewBuilder::new(&beta)
        .verify()
        .with_local_codec(Codec::Identity, verify_factory)
        .build()
        .unwrap();
    let sig = Multisig::null();
    assert_eq!(
        verify.verify(&sig, None).err().unwrap().to_string(),
        "Unsupported key algorithm: beta-protocol verify"
    );
}

/// Test that a custom key passes through serde roundtrips unchanged.
#[cfg(feature = "serde")]
#[test]
fn test_custom_key_serde_roundtrip() {
    let mk = decoded_custom_key("my-protocol", 1);

    // human-readable format
    let json = serde_json::to_string(&mk).unwrap();
    let back: Multikey = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mk);

    // binary format
    let mut cbor = Vec::new();
    ciborium::into_writer(&mk, &mut cbor).unwrap();
    let back: Multikey = ciborium::from_reader(cbor.as_slice()).unwrap();
    assert_eq!(back, mk);
}
