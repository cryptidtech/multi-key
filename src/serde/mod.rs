// SPDX-License-Identifier: Apache-2.0
//! Serde (de)serialization for [`crate::Multikey`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{Builder, EncodedMultikey, Multikey, Views, cipher, kdf, nonce};
    use multi_base::Base;
    use multi_codec::Codec;
    use multi_hash::EncodedMultihash;
    use multi_trait::Null;
    use multi_util::BaseEncoded;
    use serde::{Deserialize, Serialize};
    use serde_test::{Configure, Token, assert_tokens};
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Wrapper {
        pub map: BTreeMap<EncodedMultihash, Multikey>,
    }

    #[test]
    fn test_serde_macros() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();
        let skh = {
            let fv = sk.fingerprint_view().unwrap();
            EncodedMultihash::new(Base::Base58Btc, fv.fingerprint(Codec::Blake2S256).unwrap())
        };
        let pk = {
            let cv = sk.conv_view().unwrap();
            cv.to_public_key().unwrap()
        };
        let pkh = {
            let fv = sk.fingerprint_view().unwrap();
            EncodedMultihash::new(Base::Base58Btc, fv.fingerprint(Codec::Blake2S256).unwrap())
        };

        let mut w1 = Wrapper::default();
        w1.map.insert(skh, sk);
        w1.map.insert(pkh, pk);

        let b = serde_cbor::to_vec(&w1).unwrap();
        let w2 = serde_cbor::from_slice(b.as_slice()).unwrap();
        assert_eq!(w1, w2);
        let s = serde_json::to_string(&w1).unwrap();
        let w3 = serde_json::from_str(&s).unwrap();
        assert_eq!(w1, w3);
    }

    #[test]
    fn test_serde_compact() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        // try to get the associated public key
        let mk = {
            let conv = sk.conv_view().unwrap();

            conv.to_public_key().unwrap()
        };

        //let v: Vec<u8> = mk.clone().into();
        //println!("public key: {}", hex::encode(&v));

        assert_tokens(
            &mk.compact(),
            &[Token::BorrowedBytes(&[
                0xba, 0x24, // Multikey sigil
                0xed, 0x01, // Ed25519 public key as varuint
                0x08, // comment length
                0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79, // comment
                0x01, // 1 attribute
                0x01, // key data attributes
                0x20, // 32 bytes in the public key
                // public key bytes
                0x13, 0xe1, 0xe6, 0xe8, 0xc3, 0x53, 0x67, 0x2b, 0x75, 0x9c, 0x93, 0xc3, 0x97, 0x95,
                0x69, 0x27, 0xe1, 0x50, 0x3c, 0x6e, 0xdd, 0x73, 0xf2, 0x40, 0xcc, 0xff, 0x2b, 0x7d,
                0xd0, 0x45, 0x58, 0xb6,
            ])],
        );
    }

    #[test]
    fn test_serde_encoded_string() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let pk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &pk.readable(),
            &[Token::Str(
                "z7q2yVpRpajoAeCS88yKcpYdNB5dtDEDvKqPGXAyTEebE8qxx8Zgh8MwFcbbvbMTSjT",
            )],
        );
    }

    #[test]
    fn test_serde_readable() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        let mk = {
            let conv = sk.conv_view().unwrap();

            conv.to_public_key().unwrap()
        };

        assert_tokens(
            &mk.readable(),
            &[
                Token::Struct {
                    name: "multikey",
                    len: 3,
                },
                Token::Str("codec"),
                Token::Str("ed25519-pub"),
                Token::Str("comment"),
                Token::Str("test key"),
                Token::Str("attributes"),
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::Str("key-data"), // AttrId::KeyData
                Token::Str("f2013e1e6e8c353672b759c93c397956927e1503c6edd73f240ccff2b7dd04558b6"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_compact() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
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
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            cipher.encrypt().unwrap()
        };

        /*
                let v: Vec<u8> = mk2.clone().into();
                print!("mk2: ");
                for b in &v {
                    print!("0x{:02x}, ", b);
                }
                println!("");
        */

        // The encrypted key round-trips through serde unchanged. We no longer
        // assert exact ciphertext bytes: ChaCha20Poly1305 appends a 16-byte
        // Poly1305 tag, so the encrypted form differs from the legacy bare-stream
        // output (see test_chacha20_aead_roundtrip for the crypto itself).
        assert!(mk2.attr_view().unwrap().is_encrypted());
        let json = serde_json::to_string(&mk2).unwrap();
        let mk3: Multikey = serde_json::from_str(&json).unwrap();
        assert_eq!(mk2, mk3);
    }

    #[test]
    fn test_serde_encrypted_secret_key_readable() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
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
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();
            let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            cipher.encrypt().unwrap()
        };

        // No exact-ciphertext assertion (ChaCha20Poly1305 tag); assert the
        // encrypted key round-trips through serde unchanged.
        assert!(mk2.attr_view().unwrap().is_encrypted());
        let json = serde_json::to_string(&mk2).unwrap();
        let mk3: Multikey = serde_json::from_str(&json).unwrap();
        assert_eq!(mk2, mk3);
    }

    #[test]
    fn test_serde_encrypted_secret_key_json() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
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
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            cipher.encrypt().unwrap()
        };

        // No exact-ciphertext assertion: ChaCha20Poly1305 appends a 16-byte tag,
        // so the encrypted bytes intentionally differ from the legacy format. We
        // assert the encrypted key round-trips through JSON unchanged.
        let s = serde_json::to_string(&mk2).unwrap();
        let mk3: Multikey = serde_json::from_str(&s).unwrap();
        assert_eq!(mk2, mk3);
    }

    #[test]
    fn test_serde_encrypted_bls_secret_key_share_json() {
        /*
        let bytes = hex::decode("4b79b6a7da7cdc9fe17e368450f08ae5a5f42347f4863f2ee23404f99aa62147")
            .unwrap();
        let emk = Builder::new(Codec::Bls12381G1Priv)
            .with_comment("test key")
            .with_base_encoding(Base::Base58Btc)
            .with_key_bytes(&bytes)
            .try_build_encoded()
            .unwrap();
        println!("encoded bls private: {}", emk);
        */

        // build a secret key share multikey
        let emk = EncodedMultikey::try_from(
            "z7q2zUpseNi9mxc7jQjYD1aUdcdaAFPMenhrwDvLXotf6NJYJdNfz4zjSADxfEhSWjg",
        )
        .unwrap();
        let mk1 = emk.to_inner();

        let attr = mk1.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk1.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            cipher.encrypt().unwrap()
        };

        // No exact-ciphertext assertion (ChaCha20Poly1305 tag); assert round-trip.
        let s = serde_json::to_string(&mk2).unwrap();
        let mk3: Multikey = serde_json::from_str(&s).unwrap();
        assert_eq!(mk2, mk3);
    }

    #[test]
    fn test_chacha20_aead_roundtrip() {
        // A secret key encrypted with ChaCha20Poly1305 must decrypt back to the
        // exact plaintext, and the ciphertext must be 16 bytes longer than the
        // plaintext (the appended Poly1305 authentication tag) — proving the AEAD
        // path is active rather than the legacy bare ChaCha20 stream.
        let plain = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&plain)
            .try_build()
            .unwrap();

        let salt = hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
            .unwrap();
        let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
            .with_salt(&salt)
            .with_rounds(10)
            .try_build()
            .unwrap();
        let nonce = hex::decode("714e5abf0f7beae8aabbccdd").unwrap();
        let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
            .with_nonce(&nonce)
            .try_build()
            .unwrap();
        let ciphermk = ciphermk
            .kdf_view(&kdfmk)
            .unwrap()
            .derive_key(b"for great justice, move every zig!")
            .unwrap();

        // encrypt → must be longer by the 16-byte tag
        let enc = mk1.cipher_view(&ciphermk).unwrap().encrypt().unwrap();
        assert!(enc.attr_view().unwrap().is_encrypted());
        assert_eq!(
            enc.data_view().unwrap().key_bytes().unwrap().len(),
            plain.len() + 16
        );

        // decrypt → recovers the original plaintext
        let dec = enc.cipher_view(&ciphermk).unwrap().decrypt().unwrap();
        assert_eq!(
            dec.data_view().unwrap().secret_bytes().unwrap().as_slice(),
            plain.as_slice()
        );
    }

    #[test]
    fn test_encoded_public_key() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        // try to get the associated public key
        let pk = {
            let conv = sk.conv_view().unwrap();
            conv.to_public_key().unwrap()
        };

        // try to get the associated public key
        let mk1 = BaseEncoded::new(Base::Base58Btc, pk);
        let mk2 = EncodedMultikey::try_from(mk1.to_string().as_str()).unwrap();

        assert_eq!(mk1, mk2);
    }

    #[test]
    fn test_nonce_serde_compact() {
        let bytes = hex::decode("76895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995")
            .unwrap();
        let n = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

        assert_tokens(
            &n.compact(),
            &[Token::BorrowedBytes(&[
                187, 36, 32, 118, 137, 82, 114, 197, 206, 92, 12, 114, 181, 236, 84, 148, 78, 173,
                115, 148, 130, 248, 112, 72, 219, 191, 193, 59, 135, 48, 8, 179, 29, 89, 149,
            ])],
        );
    }

    #[test]
    fn test_nonce_serde_encoded_string() {
        let bytes = hex::decode("76895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995")
            .unwrap();
        let n = nonce::Builder::new_from_bytes(&bytes)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &n.readable(),
            &[Token::Str(
                "fbb242076895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995",
            )],
        );
    }

    #[test]
    fn test_nonce_serde_readable() {
        let bytes = hex::decode("76895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995")
            .unwrap();
        let n = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

        assert_tokens(
            &n.readable(),
            &[
                Token::Struct {
                    name: "nonce",
                    len: 1,
                },
                Token::Str("nonce"),
                Token::Str("f2076895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_null_multikey_serde_compact() {
        let mk = Multikey::null();
        assert_tokens(&mk.compact(), &[Token::BorrowedBytes(&[186, 36, 0, 0, 0])]);
    }

    #[test]
    fn test_null_multikey_serde_readable() {
        let mk = Multikey::null();
        assert_tokens(
            &mk.readable(),
            &[
                Token::Struct {
                    name: "multikey",
                    len: 3,
                },
                Token::Str("codec"),
                Token::Str("identity"),
                Token::Str("comment"),
                Token::Str(""),
                Token::Str("attributes"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_encoded_null_multikey_serde_readable() {
        let mk: EncodedMultikey = Multikey::null().into();
        assert_tokens(&mk.readable(), &[Token::Str("fba24000000")]);
    }

    #[test]
    fn test_null_nonce_serde_compact() {
        let n = nonce::Nonce::null();
        assert_tokens(&n.compact(), &[Token::BorrowedBytes(&[187, 36, 0])]);
    }

    #[test]
    fn test_null_nonce_serde_readable() {
        let n = nonce::Nonce::null();
        assert_tokens(
            &n.readable(),
            &[
                Token::Struct {
                    name: "nonce",
                    len: 1,
                },
                Token::Str("nonce"),
                Token::Str("f00"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_encoded_null_nonce_serde_readable() {
        let n: nonce::EncodedNonce = nonce::Nonce::null().into();
        assert_tokens(&n.readable(), &[Token::Str("fbb2400")]);
    }
}
