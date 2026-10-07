// SPDX-License-Identifier: Apache-2.0

//! Builder-pattern view creation over Multikeys.
//!
//! A [`ViewBuilder`] selects one view kind, optionally registers local codec
//! factories for that kind, and builds the view. It is the builder-pattern
//! alternative to the many `*_view()` methods of the [`crate::Views`] trait
//! and covers standard codecs and custom protocol keys alike.
//!
//! The three steps for a standard key:
//!
//! ```
//! use multi_codec::Codec;
//! use multi_key::{Builder, ViewBuilder};
//!
//! let mut rng = rand::rng();
//! let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
//!     .unwrap()
//!     .try_build()
//!     .unwrap();
//!
//! let signer = ViewBuilder::new(&mk).sign().build().unwrap();
//! let sig = signer.sign(b"message", false, None).unwrap();
//! let verifier = ViewBuilder::new(&mk).verify().build().unwrap();
//! verifier.verify(&sig, Some(b"message")).unwrap();
//! ```
//!
//! A custom protocol key (codec [`multi_codec::Codec::Identity`] carrying the
//! `AlgorithmName` and `KeyType` attributes from
//! cryptidtech/provenance-specifications#4) has no built-in views, so it
//! dispatches to the factory registered for its kind:
//!
//! ```
//! use multi_codec::Codec;
//! use multi_key::{AttrId, Builder, Error, Multikey, SignView, ViewBuilder};
//! use zeroize::Zeroizing;
//!
//! // a custom protocol key: codec Identity plus AlgorithmName/KeyType
//! let mut custom = Builder::new(Codec::Identity)
//!     .with_key_bytes(b"custom".as_slice())
//!     .try_build()
//!     .unwrap();
//! custom
//!     .attributes
//!     .insert(AttrId::AlgorithmName, Zeroizing::new(b"example-protocol".to_vec()));
//! custom
//!     .attributes
//!     .insert(AttrId::KeyType, Zeroizing::new(vec![1]));
//! // decode the key from wire bytes, the way a custom key usually arrives
//! let bytes: Vec<u8> = custom.clone().into();
//! let decoded = Multikey::try_from(bytes.as_ref()).unwrap();
//!
//! struct CustomSign {
//!     algorithm_name: Vec<u8>,
//! }
//!
//! impl SignView for CustomSign {
//!     fn sign(
//!         &self,
//!         _: &[u8],
//!         _: bool,
//!         _: Option<u8>,
//!     ) -> Result<multi_sig::Multisig, Error> {
//!         Err(Error::UnsupportedAlgorithm("custom".into()))
//!     }
//! }
//!
//! let view = ViewBuilder::new(&decoded)
//!     .sign()
//!     .with_local_codec(Codec::Identity, |mk| {
//!         let name = mk
//!             .attributes
//!             .get(&AttrId::AlgorithmName)
//!             .ok_or(Error::UnsupportedAlgorithm("AlgorithmName missing".into()))?;
//!         Ok(Box::new(CustomSign {
//!             algorithm_name: name.to_vec(),
//!         }))
//!     })
//!     .build()
//!     .unwrap();
//! let err = view.sign(b"message", false, None).err().unwrap();
//! assert_eq!(err.to_string(), "Unsupported key algorithm: custom");
//! ```
//!
//! # Differences from the issuing report
//!
//! The requesting report sketched a single callback,
//! `|mk, view_id| -> Box<dyn View>`. This crate has 17 distinct view traits
//! and no unified `View` trait, so an erased single callback cannot be
//! expressed type-safely. The builder realizes the same steps with a fluent
//! kind selector and a registration typed by the selected kind instead; each
//! factory receives the viewed Multikey (plus the attached second key for the
//! `cipher` and `kdf` kinds). See [`ViewKind`] for the reachable kinds.
//!
//! # Second key lifetime
//!
//! The `cipher` and `kdf` kinds store their second key by reference for the
//! builder's lifetime (`'mk`). This is slightly narrower than
//! [`crate::Views::cipher_view`]/[`crate::Views::kdf_view`], which let the
//! caller choose the overlap of the two borrows at the call site.

use crate::{
    AttrView, CipherAttrView, CipherView, ConvView, DataView, Error, FingerprintView, KdfAttrView,
    KdfView, MerkleStateView, Multikey, OpenView, SealView, SignView, ThresholdAttrView,
    ThresholdDisclosureView, ThresholdKeyView, ThresholdView, VerifyView,
    error::{AttributesError, CipherError, ConversionsError, KdfError, SealError},
    views::dispatch::{
        dispatch_attr_view, dispatch_cipher_attr_view, dispatch_cipher_view, dispatch_conv_view,
        dispatch_data_view, dispatch_disclosure_view, dispatch_fingerprint_view,
        dispatch_kdf_attr_view, dispatch_kdf_view, dispatch_merkle_state_view, dispatch_open_view,
        dispatch_seal_view, dispatch_sign_view, dispatch_threshold_attr_view,
        dispatch_threshold_key_view, dispatch_threshold_view, dispatch_verify_view,
    },
};
use multi_codec::Codec;
use std::collections::BTreeMap;

mod sealed {
    /// Types outside this module cannot implement the `ViewKind` trait.
    pub trait Sealed {}
}

/// The view kinds a [`ViewBuilder`] can produce.
///
/// One marker type implements this trait per view kind. The kind markers are
/// sealed: code outside this module cannot implement the trait.
///
/// This trait's associated type is implementation plumbing for the builder's
/// local factory table; callers select kinds with the fluent methods and never
/// name or work with this associated type.
pub trait ViewKind: sealed::Sealed {
    /// The local factory table held by a [`ViewBuilder`] for this kind.
    type Factories;
}

/// Marker for a [`ViewBuilder`] with no kind selected yet.
///
/// The kind selectors ([`ViewBuilder::attr`], [`ViewBuilder::sign`],
/// [`ViewBuilder::cipher`], ...) transform a builder of this kind into a
/// builder of the selected kind. Only kind-selected builders can register
/// local codec factories or build.
pub struct Unselected;

/// Marker for the basic-attributes view kind (`attr`), producing
/// [`Box<dyn AttrView>`].
pub struct AttrKind;

/// Marker for the cipher-attributes view kind (`cipher_attr`), producing
/// [`Box<dyn CipherAttrView>`].
pub struct CipherAttrKind;

/// Marker for the key-data view kind (`data`), producing
/// [`Box<dyn DataView>`].
pub struct DataKind;

/// Marker for the kdf-attributes view kind (`kdf_attr`), producing
/// [`Box<dyn KdfAttrView>`].
pub struct KdfAttrKind;

/// Marker for the threshold-attributes view kind (`threshold_attr`),
/// producing [`Box<dyn ThresholdAttrView>`].
pub struct ThresholdAttrKind;

/// Marker for the threshold-key-metadata view kind (`threshold_key`),
/// producing [`Box<dyn ThresholdKeyView>`].
pub struct ThresholdKeyKind;

/// Marker for the key-conversion view kind (`conv`), producing
/// [`Box<dyn ConvView>`].
pub struct ConvKind;

/// Marker for the fingerprint view kind (`fingerprint`), producing
/// [`Box<dyn FingerprintView>`].
pub struct FingerprintKind;

/// Marker for the signing view kind (`sign`), producing [`Box<dyn SignView>`].
pub struct SignKind;

/// Marker for the verification view kind (`verify`), producing
/// [`Box<dyn VerifyView>`].
pub struct VerifyKind;

/// Marker for the seal (encrypt) view kind (`seal`), producing
/// [`Box<dyn SealView>`].
pub struct SealKind;

/// Marker for the open (decrypt) view kind (`open`), producing
/// [`Box<dyn OpenView>`].
pub struct OpenKind;

/// Marker for the cipher view kind (`cipher`), producing
/// [`Box<dyn CipherView>`]. This kind needs a cipher key attached with
/// [`ViewBuilder::cipher`].
pub struct CipherKind;

/// Marker for the kdf view kind (`kdf`), producing [`Box<dyn KdfView>`]. This
/// kind needs a kdf key attached with [`ViewBuilder::kdf`].
pub struct KdfKind;

/// Marker for the threshold view kind (`threshold`), producing
/// [`Box<dyn ThresholdView>`].
pub struct ThresholdKind;

/// Marker for the threshold-disclosure view kind (`disclosure`), producing
/// [`Box<dyn ThresholdDisclosureView>`].
pub struct DisclosureKind;

/// Marker for the merkle-tree state view kind (`merkle_state`), producing
/// [`Box<dyn MerkleStateView>`].
pub struct MerkleStateKind;

impl sealed::Sealed for Unselected {}
impl ViewKind for Unselected {
    type Factories = ();
}
impl sealed::Sealed for AttrKind {}
impl ViewKind for AttrKind {
    type Factories = AttrFactories;
}
impl sealed::Sealed for CipherAttrKind {}
impl ViewKind for CipherAttrKind {
    type Factories = CipherAttrFactories;
}
impl sealed::Sealed for DataKind {}
impl ViewKind for DataKind {
    type Factories = DataFactories;
}
impl sealed::Sealed for KdfAttrKind {}
impl ViewKind for KdfAttrKind {
    type Factories = KdfAttrFactories;
}
impl sealed::Sealed for ThresholdAttrKind {}
impl ViewKind for ThresholdAttrKind {
    type Factories = ThresholdAttrFactories;
}
impl sealed::Sealed for ThresholdKeyKind {}
impl ViewKind for ThresholdKeyKind {
    type Factories = ThresholdKeyFactories;
}
impl sealed::Sealed for ConvKind {}
impl ViewKind for ConvKind {
    type Factories = ConvFactories;
}
impl sealed::Sealed for FingerprintKind {}
impl ViewKind for FingerprintKind {
    type Factories = FingerprintFactories;
}
impl sealed::Sealed for SignKind {}
impl ViewKind for SignKind {
    type Factories = SignFactories;
}
impl sealed::Sealed for VerifyKind {}
impl ViewKind for VerifyKind {
    type Factories = VerifyFactories;
}
impl sealed::Sealed for SealKind {}
impl ViewKind for SealKind {
    type Factories = SealFactories;
}
impl sealed::Sealed for OpenKind {}
impl ViewKind for OpenKind {
    type Factories = OpenFactories;
}
impl sealed::Sealed for CipherKind {}
impl ViewKind for CipherKind {
    type Factories = CipherFactories;
}
impl sealed::Sealed for KdfKind {}
impl ViewKind for KdfKind {
    type Factories = KdfFactories;
}
impl sealed::Sealed for ThresholdKind {}
impl ViewKind for ThresholdKind {
    type Factories = ThresholdFactories;
}
impl sealed::Sealed for DisclosureKind {}
impl ViewKind for DisclosureKind {
    type Factories = ThresholdDisclosureFactories;
}
impl sealed::Sealed for MerkleStateKind {}
impl ViewKind for MerkleStateKind {
    type Factories = MerkleStateFactories;
}

/// A local-codec factory for the attr view kind.
type AttrFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn AttrView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the attr view kind, keyed by codec.
type AttrFactories = BTreeMap<Codec, AttrFactory>;
/// A local-codec factory for the cipher-attributes view kind.
type CipherAttrFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn CipherAttrView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the cipher-attributes view kind, keyed by codec.
type CipherAttrFactories = BTreeMap<Codec, CipherAttrFactory>;
/// A local-codec factory for the key-data view kind.
type DataFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn DataView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the key-data view kind, keyed by codec.
type DataFactories = BTreeMap<Codec, DataFactory>;
/// A local-codec factory for the kdf-attributes view kind.
type KdfAttrFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn KdfAttrView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the kdf-attributes view kind, keyed by codec.
type KdfAttrFactories = BTreeMap<Codec, KdfAttrFactory>;
/// A local-codec factory for the threshold-attributes view kind.
type ThresholdAttrFactory = Box<
    dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn ThresholdAttrView + 'a>, Error> + Send + Sync,
>;
/// Local codec factories registered for the threshold-attributes view kind, keyed by codec.
type ThresholdAttrFactories = BTreeMap<Codec, ThresholdAttrFactory>;
/// A local-codec factory for the threshold-key-metadata view kind.
type ThresholdKeyFactory = Box<
    dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn ThresholdKeyView + 'a>, Error> + Send + Sync,
>;
/// Local codec factories registered for the threshold-key-metadata view kind, keyed by codec.
type ThresholdKeyFactories = BTreeMap<Codec, ThresholdKeyFactory>;
/// A local-codec factory for the key-conversion view kind.
type ConvFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn ConvView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the key-conversion view kind, keyed by codec.
type ConvFactories = BTreeMap<Codec, ConvFactory>;
/// A local-codec factory for the fingerprint view kind.
type FingerprintFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn FingerprintView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the fingerprint view kind, keyed by codec.
type FingerprintFactories = BTreeMap<Codec, FingerprintFactory>;
/// A local-codec factory for the signing view kind.
type SignFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn SignView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the signing view kind, keyed by codec.
type SignFactories = BTreeMap<Codec, SignFactory>;
/// A local-codec factory for the verification view kind.
type VerifyFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn VerifyView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the verification view kind, keyed by codec.
type VerifyFactories = BTreeMap<Codec, VerifyFactory>;
/// A local-codec factory for the seal view kind.
type SealFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn SealView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the seal view kind, keyed by codec.
type SealFactories = BTreeMap<Codec, SealFactory>;
/// A local-codec factory for the open view kind.
type OpenFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn OpenView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the open view kind, keyed by codec.
type OpenFactories = BTreeMap<Codec, OpenFactory>;
/// A local-codec factory for the cipher view kind. The factory receives the
/// viewed Multikey and the attached cipher key.
type CipherFactory = Box<
    dyn for<'a> Fn(&'a Multikey, &'a Multikey) -> Result<Box<dyn CipherView + 'a>, Error>
        + Send
        + Sync,
>;
/// Local codec factories registered for the cipher view kind, keyed by codec.
type CipherFactories = BTreeMap<Codec, CipherFactory>;
/// A local-codec factory for the kdf view kind. The factory receives the
/// viewed Multikey and the attached kdf key.
type KdfFactory = Box<
    dyn for<'a> Fn(&'a Multikey, &'a Multikey) -> Result<Box<dyn KdfView + 'a>, Error>
        + Send
        + Sync,
>;
/// Local codec factories registered for the kdf view kind, keyed by codec.
type KdfFactories = BTreeMap<Codec, KdfFactory>;
/// A local-codec factory for the threshold view kind.
type ThresholdFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn ThresholdView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the threshold view kind, keyed by codec.
type ThresholdFactories = BTreeMap<Codec, ThresholdFactory>;
/// A local-codec factory for the threshold-disclosure view kind.
type ThresholdDisclosureFactory = Box<
    dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn ThresholdDisclosureView + 'a>, Error>
        + Send
        + Sync,
>;
/// Local codec factories registered for the threshold-disclosure view kind, keyed by codec.
type ThresholdDisclosureFactories = BTreeMap<Codec, ThresholdDisclosureFactory>;
/// A local-codec factory for the merkle-tree state view kind.
type MerkleStateFactory =
    Box<dyn for<'a> Fn(&'a Multikey) -> Result<Box<dyn MerkleStateView + 'a>, Error> + Send + Sync>;
/// Local codec factories registered for the merkle-tree state view kind, keyed by codec.
type MerkleStateFactories = BTreeMap<Codec, MerkleStateFactory>;

/// Builder-pattern view creation over a Multikey.
///
/// Create the builder with [`ViewBuilder::new`], select a view kind with one
/// of the fluent kind selectors, optionally register local codec factories
/// with [`with_local_codec`](Self::with_local_codec), then build with
/// [`build`](Self::build):
///
/// - [`ViewBuilder::new`] + `.attr()` + `.build()` (and 14 more no-argument
///   kinds: `cipher_attr`, `data`, `kdf_attr`, `threshold_attr`,
///   `threshold_key`, `conv`, `fingerprint`, `sign`, `verify`, `seal`,
///   `open`, `threshold`, `disclosure`, `merkle_state`)
/// - `.cipher(&cipher_key)` and `.kdf(&kdf_key)` additionally attach the
///   second key their kind dispatches on. The attached key is stored by
///   reference for the builder's lifetime (`'mk`).
///
/// # Dispatch order
///
/// 1. The built-in views dispatch first, exactly as the `Views` trait
///    methods do: on the Multikey's codec, on the second key's codec for the
///    `cipher` and `kdf` kinds, and on the attribute-derived codec (the
///    `CipherCodec`/`KdfCodec` attribute value, falling back to the key's
///    codec) for the `cipher_attr` and `kdf_attr` kinds.
/// 2. A local factory registered for the codec that has no built-in view
///    applies on fallthrough only. The factory lookup key is the codec the
///    built-in dispatch actually failed on: the codec carried by the
///    fallthrough error, or the viewed Multikey's codec for the `seal` and
///    `open` kinds whose fallthrough error (`SealError::NotEncryptionKey`)
///    carries no codec. Built-in views always win: a factory registered for a
///    codec that the built-in dispatch does support is never called.
/// 3. Without a matching factory, the built-in fallthrough error propagates
///    unchanged (same variant, same codec value).
/// 4. Factory errors propagate unchanged.
///
/// A repeat `with_local_codec` call for the same kind and codec replaces the
/// earlier factory. The `disclosure` kind is codec-independent (its built-in
/// view applies to every key), so a factory registered for that kind is never
/// consulted.
///
/// # Factory contract
///
/// Factories satisfy a higher-ranked closure shape so the built view can bind
/// to the viewed (and second) key's lifetime:
/// `for<'a> Fn(&'a Multikey) -> Result<Box<dyn Trait + 'a>, Error>` for the
/// single-key kinds and
/// `for<'a> Fn(&'a Multikey, &'a Multikey) -> Result<Box<dyn Trait + 'a>, Error>`
/// for the `cipher` and `kdf` kinds. Factories must additionally be
/// `Send + Sync + 'static`, so a factory cannot capture the builder's borrows;
/// it works from owned state (a clone, an `Arc`, static data).
///
/// Note that the returned view boxes carry no `Send`/`Sync` supertrait, same
/// as the `Views` trait today. The builder itself is `Send + Sync` with and
/// without factories.
pub struct ViewBuilder<'mk, K: ViewKind = Unselected> {
    /// the Multikey being viewed
    mk: &'mk Multikey,
    /// the cipher/kdf second key; aliases the viewed Multikey until
    /// [`ViewBuilder::cipher`] or [`ViewBuilder::kdf`] attaches the real
    /// second key, which only those two kinds read
    second: &'mk Multikey,
    /// local codec factories registered for the selected kind
    local: Option<K::Factories>,
}

impl<'mk> ViewBuilder<'mk, Unselected> {
    /// Create an unselected view builder over `mk`.
    pub fn new(mk: &'mk Multikey) -> Self {
        Self {
            mk,
            second: mk,
            local: None,
        }
    }

    /// Select the basic-attributes view kind.
    pub fn attr(self) -> ViewBuilder<'mk, AttrKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the cipher-attributes view kind.
    pub fn cipher_attr(self) -> ViewBuilder<'mk, CipherAttrKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the key-data view kind.
    pub fn data(self) -> ViewBuilder<'mk, DataKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the kdf-attributes view kind.
    pub fn kdf_attr(self) -> ViewBuilder<'mk, KdfAttrKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the threshold-attributes view kind.
    pub fn threshold_attr(self) -> ViewBuilder<'mk, ThresholdAttrKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the threshold-key-metadata view kind.
    pub fn threshold_key(self) -> ViewBuilder<'mk, ThresholdKeyKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the key-conversion view kind.
    pub fn conv(self) -> ViewBuilder<'mk, ConvKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the fingerprint view kind.
    pub fn fingerprint(self) -> ViewBuilder<'mk, FingerprintKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the signing view kind.
    pub fn sign(self) -> ViewBuilder<'mk, SignKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the verification view kind.
    pub fn verify(self) -> ViewBuilder<'mk, VerifyKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the seal (encrypt) view kind.
    pub fn seal(self) -> ViewBuilder<'mk, SealKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the open (decrypt) view kind.
    pub fn open(self) -> ViewBuilder<'mk, OpenKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the threshold view kind.
    pub fn threshold(self) -> ViewBuilder<'mk, ThresholdKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the threshold-disclosure view kind.
    pub fn disclosure(self) -> ViewBuilder<'mk, DisclosureKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the merkle-tree state view kind.
    pub fn merkle_state(self) -> ViewBuilder<'mk, MerkleStateKind> {
        ViewBuilder {
            mk: self.mk,
            second: self.second,
            local: None,
        }
    }

    /// Select the cipher view kind and attach the cipher key this kind
    /// encrypts and decrypts with. The key is stored by reference for the
    /// builder's lifetime.
    pub fn cipher(self, cipher: &'mk Multikey) -> ViewBuilder<'mk, CipherKind> {
        ViewBuilder {
            mk: self.mk,
            second: cipher,
            local: None,
        }
    }

    /// Select the kdf view kind and attach the kdf parameter key this kind
    /// derives with. The key is stored by reference for the builder's
    /// lifetime.
    pub fn kdf(self, kdf: &'mk Multikey) -> ViewBuilder<'mk, KdfKind> {
        ViewBuilder {
            mk: self.mk,
            second: kdf,
            local: None,
        }
    }
}

impl<'mk> ViewBuilder<'mk, AttrKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in attr dispatch reports
    /// [`AttributesError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn AttrView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the basic-attributes view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn AttrView + 'mk>, Error> {
        match dispatch_attr_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Attributes(AttributesError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Attributes(AttributesError::UnsupportedCodec(codec))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, CipherAttrKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in cipher-attr dispatch reports
    /// [`CipherError::UnsupportedCodec`]. The dispatch (and the factory
    /// lookup) key on the codec derived from the `CipherCodec` attribute,
    /// falling back to the viewed Multikey's codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn CipherAttrView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the cipher-attributes view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn CipherAttrView + 'mk>, Error> {
        match dispatch_cipher_attr_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Cipher(CipherError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Cipher(CipherError::UnsupportedCodec(codec))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, DataKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in data dispatch reports
    /// [`ConversionsError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn DataView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the key-data view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn DataView + 'mk>, Error> {
        match dispatch_data_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Conversions(ConversionsError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Conversions(ConversionsError::UnsupportedCodec(
                        codec,
                    ))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, KdfAttrKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in kdf-attr dispatch reports
    /// [`KdfError::UnsupportedCodec`]. The dispatch (and the factory lookup)
    /// key on the codec derived from the `KdfCodec` attribute, falling back to
    /// the viewed Multikey's codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn KdfAttrView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the kdf-attributes view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn KdfAttrView + 'mk>, Error> {
        match dispatch_kdf_attr_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Kdf(KdfError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Kdf(KdfError::UnsupportedCodec(codec))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, ThresholdAttrKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in threshold-attr dispatch
    /// reports [`ConversionsError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn ThresholdAttrView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the threshold-attributes view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn ThresholdAttrView + 'mk>, Error> {
        match dispatch_threshold_attr_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Conversions(ConversionsError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Conversions(ConversionsError::UnsupportedCodec(
                        codec,
                    ))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, ThresholdKeyKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in threshold-key dispatch
    /// reports [`ConversionsError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn ThresholdKeyView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the threshold-key metadata view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn ThresholdKeyView + 'mk>, Error> {
        match dispatch_threshold_key_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Conversions(ConversionsError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Conversions(ConversionsError::UnsupportedCodec(
                        codec,
                    ))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, ConvKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in conversion dispatch reports
    /// [`ConversionsError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn ConvView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the key-conversion view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn ConvView + 'mk>, Error> {
        match dispatch_conv_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Conversions(ConversionsError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Conversions(ConversionsError::UnsupportedCodec(
                        codec,
                    ))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, FingerprintKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in fingerprint dispatch reports
    /// [`ConversionsError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn FingerprintView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the fingerprint view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn FingerprintView + 'mk>, Error> {
        match dispatch_fingerprint_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Conversions(ConversionsError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Conversions(ConversionsError::UnsupportedCodec(
                        codec,
                    ))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, SignKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in signing dispatch reports
    /// [`ConversionsError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn SignView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the signing view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn SignView + 'mk>, Error> {
        match dispatch_sign_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Conversions(ConversionsError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Conversions(ConversionsError::UnsupportedCodec(
                        codec,
                    ))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, VerifyKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in verify dispatch reports
    /// [`ConversionsError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn VerifyView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the verification view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn VerifyView + 'mk>, Error> {
        match dispatch_verify_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Conversions(ConversionsError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Conversions(ConversionsError::UnsupportedCodec(
                        codec,
                    ))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, SealKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in seal dispatch reports
    /// [`SealError::NotEncryptionKey`], whose fallthrough error carries no
    /// codec, so the factory lookup keys on the viewed Multikey's codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn SealView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the seal (encrypt) view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn SealView + 'mk>, Error> {
        match dispatch_seal_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Seal(SealError::NotEncryptionKey)) => {
                match self.local.as_ref().and_then(|f| f.get(&self.mk.codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Seal(SealError::NotEncryptionKey)),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, OpenKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in open dispatch reports
    /// [`SealError::NotEncryptionKey`], whose fallthrough error carries no
    /// codec, so the factory lookup keys on the viewed Multikey's codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn OpenView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the open (decrypt) view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn OpenView + 'mk>, Error> {
        match dispatch_open_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Seal(SealError::NotEncryptionKey)) => {
                match self.local.as_ref().and_then(|f| f.get(&self.mk.codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Seal(SealError::NotEncryptionKey)),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, CipherKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in cipher dispatch reports
    /// [`CipherError::UnsupportedCodec`] for the attached cipher key's codec.
    /// The factory receives the viewed Multikey and the attached cipher key.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey, &'a Multikey) -> Result<Box<dyn CipherView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the cipher view for the viewed Multikey and the attached second
    /// key.
    pub fn build(self) -> Result<Box<dyn CipherView + 'mk>, Error> {
        match dispatch_cipher_view(self.mk, self.second) {
            Ok(view) => Ok(view),
            Err(Error::Cipher(CipherError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk, self.second),
                    None => Err(Error::Cipher(CipherError::UnsupportedCodec(codec))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, KdfKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in kdf dispatch reports
    /// [`KdfError::UnsupportedCodec`] for the attached kdf key's codec. The
    /// factory receives the viewed Multikey and the attached kdf key.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey, &'a Multikey) -> Result<Box<dyn KdfView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the kdf view for the viewed Multikey and the attached second
    /// key.
    pub fn build(self) -> Result<Box<dyn KdfView + 'mk>, Error> {
        match dispatch_kdf_view(self.mk, self.second) {
            Ok(view) => Ok(view),
            Err(Error::Kdf(KdfError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk, self.second),
                    None => Err(Error::Kdf(KdfError::UnsupportedCodec(codec))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, ThresholdKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in threshold dispatch reports
    /// [`ConversionsError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn ThresholdView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the threshold view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn ThresholdView + 'mk>, Error> {
        match dispatch_threshold_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Conversions(ConversionsError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Conversions(ConversionsError::UnsupportedCodec(
                        codec,
                    ))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl<'mk> ViewBuilder<'mk, DisclosureKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The built-in disclosure view is codec-independent, so the factory is
    /// never consulted. Registration is accepted to keep the builder API
    /// uniform across kinds; it has no effect.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn ThresholdDisclosureView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the threshold-disclosure view for the viewed Multikey.
    ///
    /// The disclosure view is codec-independent: the built-in view applies to
    /// every key and local factories are never consulted.
    pub fn build(self) -> Result<Box<dyn ThresholdDisclosureView + 'mk>, Error> {
        Ok(dispatch_disclosure_view(self.mk))
    }
}

impl<'mk> ViewBuilder<'mk, MerkleStateKind> {
    /// Set a local-codec factory for this kind, replacing any factory already
    /// registered for `codec`.
    ///
    /// The factory applies only when the built-in merkle-state dispatch
    /// reports [`ConversionsError::UnsupportedCodec`] for a codec.
    pub fn with_local_codec<F>(mut self, codec: Codec, factory: F) -> Self
    where
        F: for<'a> Fn(&'a Multikey) -> Result<Box<dyn MerkleStateView + 'a>, Error>
            + Send
            + Sync
            + 'static,
    {
        self.local
            .get_or_insert_with(BTreeMap::new)
            .insert(codec, Box::new(factory));
        self
    }

    /// Build the merkle-tree state view for the viewed Multikey.
    pub fn build(self) -> Result<Box<dyn MerkleStateView + 'mk>, Error> {
        match dispatch_merkle_state_view(self.mk) {
            Ok(view) => Ok(view),
            Err(Error::Conversions(ConversionsError::UnsupportedCodec(codec))) => {
                match self.local.as_ref().and_then(|f| f.get(&codec)) {
                    Some(factory) => factory(self.mk),
                    None => Err(Error::Conversions(ConversionsError::UnsupportedCodec(
                        codec,
                    ))),
                }
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttrId, Builder, KEY_CODECS, ThresholdDisclosure};
    use multi_sig::Multisig;
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroizing;

    type Recorder = Arc<Mutex<Vec<String>>>;

    fn recorder() -> Recorder {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn record(rec: &Recorder, entry: &str) {
        rec.lock().unwrap().push(entry.to_string());
    }

    /// A custom protocol key: codec `Identity` plus the `AlgorithmName` and
    /// `KeyType` attributes, decoded from wire bytes the way such keys arrive.
    fn custom_key(algorithm_name: &str) -> Multikey {
        let mut mk = Builder::new(Codec::Identity)
            .with_key_bytes("custom-key-material")
            .try_build()
            .unwrap();
        mk.attributes.insert(
            AttrId::AlgorithmName,
            Zeroizing::new(algorithm_name.as_bytes().to_vec()),
        );
        mk.attributes
            .insert(AttrId::KeyType, Zeroizing::new(vec![1]));
        let bytes: Vec<u8> = mk.clone().into();
        Multikey::try_from(bytes.as_ref()).unwrap()
    }

    fn ed25519_key() -> Multikey {
        let mut rng = rand::rng();
        Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap()
    }

    fn chacha_key() -> Multikey {
        let mut mk = Builder::new(Codec::Chacha20Poly1305)
            .with_key_bytes("chacha-key-material-32-bytes-x")
            .try_build()
            .unwrap();
        mk.attributes
            .insert(AttrId::CipherNonce, Zeroizing::new(vec![0u8; 12]));
        mk
    }

    struct NoSign;
    impl SignView for NoSign {
        fn sign(&self, _: &[u8], _: bool, _: Option<u8>) -> Result<Multisig, Error> {
            Err(Error::UnsupportedAlgorithm("NoSign".into()))
        }
    }

    struct NoCipher;
    impl CipherView for NoCipher {
        fn decrypt(&self) -> Result<Multikey, Error> {
            Err(Error::UnsupportedAlgorithm("NoCipher.decrypt".into()))
        }
        fn encrypt(&self) -> Result<Multikey, Error> {
            Err(Error::UnsupportedAlgorithm("NoCipher.encrypt".into()))
        }
    }

    struct NoKdf;
    impl KdfView for NoKdf {
        fn derive_key(&self, _: &[u8]) -> Result<Multikey, Error> {
            Err(Error::UnsupportedAlgorithm("NoKdf.derive_key".into()))
        }
    }

    struct NoCipherAttr;
    impl CipherAttrView for NoCipherAttr {
        fn cipher_codec(&self) -> Result<Codec, Error> {
            Err(Error::UnsupportedAlgorithm(
                "NoCipherAttr.cipher_codec".into(),
            ))
        }
        fn nonce_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
            Err(Error::UnsupportedAlgorithm(
                "NoCipherAttr.nonce_bytes".into(),
            ))
        }
        fn key_length(&self) -> Result<usize, Error> {
            Err(Error::UnsupportedAlgorithm(
                "NoCipherAttr.key_length".into(),
            ))
        }
    }

    struct NoKdfAttr;
    impl KdfAttrView for NoKdfAttr {
        fn kdf_codec(&self) -> Result<Codec, Error> {
            Err(Error::UnsupportedAlgorithm("NoKdfAttr.kdf_codec".into()))
        }
        fn salt_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
            Err(Error::UnsupportedAlgorithm("NoKdfAttr.salt_bytes".into()))
        }
        fn rounds(&self) -> Result<usize, Error> {
            Err(Error::UnsupportedAlgorithm("NoKdfAttr.rounds".into()))
        }
    }

    struct NoDisclosure;
    impl ThresholdDisclosureView for NoDisclosure {
        fn disclosure_mode(&self) -> Result<ThresholdDisclosure, Error> {
            Err(Error::UnsupportedAlgorithm(
                "NoDisclosure.disclosure_mode".into(),
            ))
        }
        fn read_threshold_params(&self, _: Option<&Multikey>) -> Result<(usize, usize), Error> {
            Err(Error::UnsupportedAlgorithm(
                "NoDisclosure.read_threshold_params".into(),
            ))
        }
        fn to_disclosure(
            &self,
            _: ThresholdDisclosure,
            _: Option<&Multikey>,
            _: Option<&Multikey>,
        ) -> Result<Multikey, Error> {
            Err(Error::UnsupportedAlgorithm(
                "NoDisclosure.to_disclosure".into(),
            ))
        }
    }

    struct NoSeal;
    impl SealView for NoSeal {
        fn seal(&self, _: &[u8], _: Codec, _: &[u8]) -> Result<(Vec<u8>, Option<Multikey>), Error> {
            Err(Error::UnsupportedAlgorithm("NoSeal.seal".into()))
        }
    }

    struct NoOpen;
    impl OpenView for NoOpen {
        fn open(
            &self,
            _: &[u8],
            _: Option<&Multikey>,
            _: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, Error> {
            Err(Error::UnsupportedAlgorithm("NoOpen.open".into()))
        }
    }

    #[test]
    fn test_builder_matches_shim() {
        for codec in KEY_CODECS {
            let mut rng = rand::rng();
            let mk = Builder::new_from_random_bytes(codec, &mut rng)
                .unwrap()
                .try_build()
                .unwrap();

            // the basic-attributes view is identical to the shim (which
            // delegates to the dispatch core)
            let shim = dispatch_attr_view(&mk).unwrap();
            let built = ViewBuilder::new(&mk).attr().build().unwrap();
            assert_eq!(shim.is_encrypted(), built.is_encrypted());
            assert_eq!(shim.is_public_key(), built.is_public_key());
            assert_eq!(shim.is_secret_key(), built.is_secret_key());
            assert_eq!(shim.is_secret_key_share(), built.is_secret_key_share());

            // the key-data view is identical to the shim
            let shim = dispatch_data_view(&mk).unwrap();
            let built = ViewBuilder::new(&mk).data().build().unwrap();
            assert_eq!(shim.key_bytes().unwrap(), built.key_bytes().unwrap());
            assert_eq!(shim.secret_bytes().unwrap(), built.secret_bytes().unwrap());
        }
    }

    #[test]
    fn test_cipher_attr_matches_shim() {
        let mk = chacha_key();

        // built-in path: both construct the chacha20 view
        let shim = dispatch_cipher_attr_view(&mk).unwrap();
        let built = ViewBuilder::new(&mk).cipher_attr().build().unwrap();
        assert_eq!(shim.cipher_codec().unwrap(), built.cipher_codec().unwrap());
        assert_eq!(
            shim.nonce_bytes().unwrap().len(),
            built.nonce_bytes().unwrap().len()
        );
        assert_eq!(shim.key_length().unwrap(), built.key_length().unwrap());

        // a signing codec has no cipher-attributes view: same error as the shim
        let mk = ed25519_key();
        let shim = dispatch_cipher_attr_view(&mk).err().unwrap();
        let built = ViewBuilder::new(&mk).cipher_attr().build().err().unwrap();
        assert_eq!(shim.to_string(), built.to_string());

        // a signing codec has no kdf-attributes view: same error as the shim
        let shim = dispatch_kdf_attr_view(&mk).err().unwrap();
        let built = ViewBuilder::new(&mk).kdf_attr().build().err().unwrap();
        assert_eq!(shim.to_string(), built.to_string());
    }

    #[test]
    fn test_unsupported_matches_shim_error() {
        // a DKG share codec has no built-in sign view
        let mk = Builder::new(Codec::Ed25519ThreshPrivShare)
            .with_key_bytes("share")
            .try_build()
            .unwrap();
        let shim = dispatch_sign_view(&mk).err().unwrap();
        let built = ViewBuilder::new(&mk).sign().build().err().unwrap();
        assert_eq!(shim.to_string(), built.to_string());
        assert!(matches!(
            built,
            Error::Conversions(ConversionsError::UnsupportedCodec(_))
        ));

        // the same key also has no threshold view
        let shim = dispatch_threshold_view(&mk).err().unwrap();
        let built = ViewBuilder::new(&mk).threshold().build().err().unwrap();
        assert_eq!(shim.to_string(), built.to_string());

        // a signing codec is not a seal/open key: exact variant preserved
        let mk = ed25519_key();
        let shim = dispatch_seal_view(&mk).err().unwrap();
        let built = ViewBuilder::new(&mk).seal().build().err().unwrap();
        assert_eq!(shim.to_string(), built.to_string());
        assert!(matches!(built, Error::Seal(SealError::NotEncryptionKey)));

        // a signing codec has no merkle state either
        let shim = dispatch_merkle_state_view(&mk).err().unwrap();
        let built = ViewBuilder::new(&mk).merkle_state().build().err().unwrap();
        assert_eq!(shim.to_string(), built.to_string());
    }

    #[test]
    fn test_custom_key_factory() {
        let mk = custom_key("example-protocol");
        let rec = recorder();
        let factory_rec = rec.clone();
        let view = ViewBuilder::new(&mk)
            .sign()
            .with_local_codec(Codec::Identity, move |key: &Multikey| {
                let name = key
                    .attributes
                    .get(&AttrId::AlgorithmName)
                    .map(|v| v.as_slice().to_vec())
                    .unwrap_or_default();
                record(&factory_rec, &String::from_utf8(name).unwrap_or_default());
                Ok(Box::new(NoSign))
            })
            .build()
            .unwrap();

        // the factory saw the decoded custom key's AlgorithmName attribute
        assert_eq!(rec.lock().unwrap().as_slice(), ["example-protocol"]);

        // the built view is the factory's view
        let err = view.sign(b"msg", false, None).err().unwrap();
        assert_eq!(err.to_string(), "Unsupported key algorithm: NoSign");
    }

    #[test]
    fn test_cipher_factory_gets_second_key() {
        let mk = custom_key("viewed-key");
        let ck = custom_key("cipher-key");
        let rec = recorder();
        let factory_rec = rec.clone();
        let view = ViewBuilder::new(&mk)
            .cipher(&ck)
            .with_local_codec(Codec::Identity, move |mk: &Multikey, cipher: &Multikey| {
                let viewed = mk
                    .attributes
                    .get(&AttrId::AlgorithmName)
                    .map(|v| v.as_slice().to_vec())
                    .unwrap_or_default();
                let attached = cipher
                    .attributes
                    .get(&AttrId::AlgorithmName)
                    .map(|v| v.as_slice().to_vec())
                    .unwrap_or_default();
                record(
                    &factory_rec,
                    &format!(
                        "{}|{}",
                        String::from_utf8(viewed).unwrap_or_default(),
                        String::from_utf8(attached).unwrap_or_default()
                    ),
                );
                Ok(Box::new(NoCipher))
            })
            .build()
            .unwrap();

        // the factory received the viewed key and the attached cipher key
        assert_eq!(rec.lock().unwrap().as_slice(), ["viewed-key|cipher-key"]);

        // the built view is the factory's view
        let err = view.decrypt().err().unwrap();
        assert_eq!(
            err.to_string(),
            "Unsupported key algorithm: NoCipher.decrypt"
        );
    }

    #[test]
    fn test_kdf_factory_gets_second_key() {
        let mk = custom_key("viewed-key");
        let kk = custom_key("kdf-key");
        let rec = recorder();
        let factory_rec = rec.clone();
        let view = ViewBuilder::new(&mk)
            .kdf(&kk)
            .with_local_codec(Codec::Identity, move |mk: &Multikey, kdf: &Multikey| {
                let viewed = mk
                    .attributes
                    .get(&AttrId::AlgorithmName)
                    .map(|v| v.as_slice().to_vec())
                    .unwrap_or_default();
                let attached = kdf
                    .attributes
                    .get(&AttrId::AlgorithmName)
                    .map(|v| v.as_slice().to_vec())
                    .unwrap_or_default();
                record(
                    &factory_rec,
                    &format!(
                        "{}|{}",
                        String::from_utf8(viewed).unwrap_or_default(),
                        String::from_utf8(attached).unwrap_or_default()
                    ),
                );
                Ok(Box::new(NoKdf))
            })
            .build()
            .unwrap();

        // the factory received the viewed key and the attached kdf key
        assert_eq!(rec.lock().unwrap().as_slice(), ["viewed-key|kdf-key"]);

        // the built view is the factory's view
        let err = view.derive_key(b"passphrase").err().unwrap();
        assert_eq!(
            err.to_string(),
            "Unsupported key algorithm: NoKdf.derive_key"
        );
    }

    #[test]
    fn test_builtin_wins() {
        let mk = ed25519_key();
        let rec = recorder();
        let factory_rec = rec.clone();
        let signer = ViewBuilder::new(&mk)
            .sign()
            .with_local_codec(Codec::Ed25519Priv, move |_: &Multikey| {
                record(&factory_rec, "called");
                Ok(Box::new(NoSign))
            })
            .build()
            .unwrap();

        // a factory registered for a supported standard codec is never called
        assert!(rec.lock().unwrap().is_empty());

        // the built-in view works: sign with the builder, verify with the
        // shim's dispatch path
        let sig = signer.sign(b"hello", false, None).unwrap();
        dispatch_verify_view(&mk)
            .unwrap()
            .verify(&sig, Some(b"hello"))
            .unwrap();

        // and the other way around
        let sig = dispatch_sign_view(&mk)
            .unwrap()
            .sign(b"hello", false, None)
            .unwrap();
        ViewBuilder::new(&mk)
            .verify()
            .build()
            .unwrap()
            .verify(&sig, Some(b"hello"))
            .unwrap();
    }

    #[test]
    fn test_factory_error_propagates() {
        let mk = custom_key("propagates");
        let built = ViewBuilder::new(&mk)
            .sign()
            .with_local_codec(Codec::Identity, |_: &Multikey| {
                Err(Error::UnsupportedAlgorithm("factory failure".into()))
            })
            .build();
        assert!(matches!(built, Err(Error::UnsupportedAlgorithm(s)) if s == "factory failure"));
    }

    #[test]
    fn test_last_registration_wins() {
        let mk = custom_key("replaces");
        let rec = recorder();
        let first = rec.clone();
        let second = rec.clone();
        let view = ViewBuilder::new(&mk)
            .sign()
            .with_local_codec(Codec::Identity, move |_: &Multikey| {
                record(&first, "first");
                Ok(Box::new(NoSign))
            })
            .with_local_codec(Codec::Identity, move |_: &Multikey| {
                record(&second, "second");
                Ok(Box::new(NoSign))
            })
            .build()
            .unwrap();

        // the second factory replaced the first for the same kind and codec
        assert_eq!(rec.lock().unwrap().as_slice(), ["second"]);
        let err = view.sign(b"msg", false, None).err().unwrap();
        assert_eq!(err.to_string(), "Unsupported key algorithm: NoSign");
    }

    #[test]
    fn test_cipher_attr_factory_lookup_key() {
        // the key's CipherCodec attribute names Ed25519Pub: that derived codec
        // is what the built-in dispatch matches on and what the factory
        // lookup keys on
        let mut mk = custom_key("attribute-derived");
        mk.attributes.insert(
            AttrId::CipherCodec,
            Zeroizing::new(Vec::from(Codec::Ed25519Pub)),
        );

        // a factory registered for the attribute-derived codec applies
        let rec = recorder();
        let factory_rec = rec.clone();
        let view = ViewBuilder::new(&mk)
            .cipher_attr()
            .with_local_codec(Codec::Ed25519Pub, move |_: &Multikey| {
                record(&factory_rec, "called");
                Ok(Box::new(NoCipherAttr))
            })
            .build()
            .unwrap();
        assert_eq!(rec.lock().unwrap().as_slice(), ["called"]);
        let err = view.cipher_codec().err().unwrap();
        assert_eq!(
            err.to_string(),
            "Unsupported key algorithm: NoCipherAttr.cipher_codec"
        );

        // a factory registered for the key's own codec is not consulted
        let rec = recorder();
        let factory_rec = rec.clone();
        let built = ViewBuilder::new(&mk)
            .cipher_attr()
            .with_local_codec(Codec::Identity, move |_: &Multikey| {
                record(&factory_rec, "called");
                Ok(Box::new(NoCipherAttr))
            })
            .build();
        assert!(rec.lock().unwrap().is_empty());
        // the fallthrough error matches the shim and names the derived codec
        assert!(matches!(
            &built,
            Err(Error::Cipher(CipherError::UnsupportedCodec(
                Codec::Ed25519Pub
            )))
        ));
        let shim = dispatch_cipher_attr_view(&mk).err().unwrap();
        assert_eq!(shim.to_string(), built.err().unwrap().to_string());
    }

    #[test]
    fn test_kdf_attr_factory_lookup_key() {
        // the key's KdfCodec attribute names Ed25519Priv: that derived codec
        // is what the built-in dispatch matches on and what the factory
        // lookup keys on
        let mut mk = custom_key("attribute-derived");
        mk.attributes.insert(
            AttrId::KdfCodec,
            Zeroizing::new(Vec::from(Codec::Ed25519Priv)),
        );

        // no factory: the fallthrough error matches the shim and names the
        // derived codec
        let shim = dispatch_kdf_attr_view(&mk).err().unwrap();
        let built = ViewBuilder::new(&mk).kdf_attr().build().err().unwrap();
        assert!(matches!(
            built,
            Error::Kdf(KdfError::UnsupportedCodec(Codec::Ed25519Priv))
        ));
        assert_eq!(shim.to_string(), built.to_string());

        // a factory registered for the derived codec applies
        let rec = recorder();
        let factory_rec = rec.clone();
        let view = ViewBuilder::new(&mk)
            .kdf_attr()
            .with_local_codec(Codec::Ed25519Priv, move |_: &Multikey| {
                record(&factory_rec, "called");
                Ok(Box::new(NoKdfAttr))
            })
            .build()
            .unwrap();
        assert_eq!(rec.lock().unwrap().as_slice(), ["called"]);
        let err = view.rounds().err().unwrap();
        assert_eq!(
            err.to_string(),
            "Unsupported key algorithm: NoKdfAttr.rounds"
        );

        // a factory registered for the key's own codec is not consulted
        let rec = recorder();
        let factory_rec = rec.clone();
        let built = ViewBuilder::new(&mk)
            .kdf_attr()
            .with_local_codec(Codec::Identity, move |_: &Multikey| {
                record(&factory_rec, "called");
                Ok(Box::new(NoKdfAttr))
            })
            .build();
        assert!(rec.lock().unwrap().is_empty());
        assert!(matches!(
            built,
            Err(Error::Kdf(KdfError::UnsupportedCodec(Codec::Ed25519Priv)))
        ));
    }

    #[test]
    fn test_cipher_attr_factory_lookup_falls_back_to_key_codec() {
        // without a CipherCodec attribute the derived codec falls back to the
        // key's own codec, and that is what the factory lookup keys on
        let mk = custom_key("no-cipher-attr");
        let rec = recorder();
        let factory_rec = rec.clone();
        let view = ViewBuilder::new(&mk)
            .cipher_attr()
            .with_local_codec(Codec::Identity, move |_: &Multikey| {
                record(&factory_rec, "called");
                Ok(Box::new(NoCipherAttr))
            })
            .build()
            .unwrap();
        assert_eq!(rec.lock().unwrap().as_slice(), ["called"]);
        let err = view.key_length().err().unwrap();
        assert_eq!(
            err.to_string(),
            "Unsupported key algorithm: NoCipherAttr.key_length"
        );
    }

    #[test]
    fn test_disclosure_factory_never_consulted() {
        let mk = ed25519_key();
        let rec = recorder();
        let factory_rec = rec.clone();
        let view = ViewBuilder::new(&mk)
            .disclosure()
            .with_local_codec(Codec::Ed25519Priv, move |_: &Multikey| {
                record(&factory_rec, "called");
                Ok(Box::new(NoDisclosure))
            })
            .build()
            .unwrap();

        // the disclosure view is codec-independent: the factory is never
        // consulted and the built-in view applies
        assert!(rec.lock().unwrap().is_empty());
        let mode = view.disclosure_mode().unwrap();
        assert_eq!(mode, ThresholdDisclosure::Full);
    }

    #[test]
    fn test_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        // the type is Send + Sync with or without factories: the factory
        // table is bounded Send + Sync and only ever holds the same type
        assert_send::<ViewBuilder<'static, Unselected>>();
        assert_sync::<ViewBuilder<'static, Unselected>>();
        assert_send::<ViewBuilder<'static, SignKind>>();
        assert_sync::<ViewBuilder<'static, SignKind>>();
        assert_send::<ViewBuilder<'static, CipherKind>>();
        assert_sync::<ViewBuilder<'static, CipherKind>>();

        // a builder that borrows keys and holds a registered factory moves
        // across threads too
        let mk = custom_key("threaded");
        let builder = ViewBuilder::new(&mk)
            .sign()
            .with_local_codec(Codec::Identity, |_: &Multikey| Ok(Box::new(NoSign)));
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let view = builder.build().unwrap();
                assert!(view.sign(b"msg", false, None).is_err());
            });
        });

        // and so does a factory-less builder
        let mk = ed25519_key();
        let builder = ViewBuilder::new(&mk).attr();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                assert!(builder.build().is_ok());
            });
        });
    }

    #[test]
    fn test_seal_open_factory_keyed_on_key_codec() {
        // a signing codec is not an encryption key: seal and open fall
        // through with NotEncryptionKey, whose error carries no codec, so the
        // factory lookup keys on the viewed Multikey's codec
        let mk = ed25519_key();
        let rec = recorder();
        let factory_rec = rec.clone();
        let view = ViewBuilder::new(&mk)
            .seal()
            .with_local_codec(Codec::Ed25519Priv, move |_: &Multikey| {
                record(&factory_rec, "seal-called");
                Ok(Box::new(NoSeal))
            })
            .build()
            .unwrap();
        assert_eq!(rec.lock().unwrap().as_slice(), ["seal-called"]);
        let err = view
            .seal(b"plaintext", Codec::Chacha20Poly1305, b"aad")
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "Unsupported key algorithm: NoSeal.seal");

        let rec = recorder();
        let factory_rec = rec.clone();
        let view = ViewBuilder::new(&mk)
            .open()
            .with_local_codec(Codec::Ed25519Priv, move |_: &Multikey| {
                record(&factory_rec, "open-called");
                Ok(Box::new(NoOpen))
            })
            .build()
            .unwrap();
        assert_eq!(rec.lock().unwrap().as_slice(), ["open-called"]);
        let err = view.open(b"sealed", None, b"aad").err().unwrap();
        assert_eq!(err.to_string(), "Unsupported key algorithm: NoOpen.open");

        // a factory registered for a codec the key does not carry is not
        // consulted; the exact fallthrough error returns
        let built = ViewBuilder::new(&mk)
            .seal()
            .with_local_codec(Codec::Ed25519Pub, |_: &Multikey| Ok(Box::new(NoSeal)))
            .build();
        assert!(matches!(
            built,
            Err(Error::Seal(SealError::NotEncryptionKey))
        ));
    }

    #[test]
    fn test_cipher_kdf_factory_lookup_key_is_second_key_codec() {
        // the cipher and kdf kinds dispatch on the SECOND key's codec, so the
        // factory lookup keys on that codec, not the viewed key's codec
        let mk = custom_key("viewed-key");
        let ck = ed25519_key(); // a signing codec: no built-in cipher or kdf view
        let rec = recorder();
        let factory_rec = rec.clone();
        let built = ViewBuilder::new(&mk)
            .cipher(&ck)
            .with_local_codec(Codec::Ed25519Priv, move |_: &Multikey, _: &Multikey| {
                record(&factory_rec, "called");
                Err(Error::UnsupportedAlgorithm("second-key factory".into()))
            })
            .build();
        assert_eq!(rec.lock().unwrap().as_slice(), ["called"]);
        assert!(matches!(built, Err(Error::UnsupportedAlgorithm(s)) if s == "second-key factory"));

        // a factory keyed on the VIEWED key's codec is never consulted; the
        // fallthrough error matches the shim and names the second key's codec
        let rec = recorder();
        let factory_rec = rec.clone();
        let built = ViewBuilder::new(&mk)
            .cipher(&ck)
            .with_local_codec(Codec::Identity, move |_: &Multikey, _: &Multikey| {
                record(&factory_rec, "called");
                Err(Error::UnsupportedAlgorithm("viewed-key factory".into()))
            })
            .build();
        assert!(rec.lock().unwrap().is_empty());
        assert!(matches!(
            &built,
            Err(Error::Cipher(CipherError::UnsupportedCodec(
                Codec::Ed25519Priv
            )))
        ));
        let shim = dispatch_cipher_view(&mk, &ck).err().unwrap();
        assert_eq!(shim.to_string(), built.err().unwrap().to_string());

        // the kdf kind keys on the kdf key's codec the same way
        let rec = recorder();
        let factory_rec = rec.clone();
        let built = ViewBuilder::new(&mk)
            .kdf(&ck)
            .with_local_codec(Codec::Ed25519Priv, move |_: &Multikey, _: &Multikey| {
                record(&factory_rec, "called");
                Err(Error::UnsupportedAlgorithm("kdf second-key factory".into()))
            })
            .build();
        assert_eq!(rec.lock().unwrap().as_slice(), ["called"]);
        assert!(
            matches!(built, Err(Error::UnsupportedAlgorithm(s)) if s == "kdf second-key factory")
        );
    }
}
