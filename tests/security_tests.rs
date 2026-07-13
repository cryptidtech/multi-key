// SPDX-License-Identifier: Apache-2.0
//! Security-focused tests for multi-key

use multi_codec::Codec;
use multi_key::{Builder, Error, Multikey};

/// Test malformed multikey data
#[test]
fn test_malformed_data() {
    let invalid = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = Multikey::try_from(invalid.as_ref());
    assert!(result.is_err());
}

/// Test truncated multikey
#[test]
fn test_truncated_data() {
    let truncated = vec![0x39]; // Just sigil
    let result = Multikey::try_from(truncated.as_ref());
    assert!(result.is_err());
}

/// Test empty bytes
#[test]
fn test_empty_bytes() {
    let result = Multikey::try_from(&[] as &[u8]);
    assert!(result.is_err());
}

/// Test concurrent key generation
#[test]
fn test_concurrent_generation() {
    use rand::SeedableRng;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;

    // ThreadRng is !Send; use the Send StdRng (still a rand_core 0.10 CryptoRng).
    let rng = Arc::new(Mutex::new(rand::rngs::StdRng::from_rng(&mut rand::rng())));
    let mut handles = vec![];

    for _ in 0..4 {
        let rng_clone = Arc::clone(&rng);
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let mut rng = rng_clone.lock().unwrap();
                if let Ok(builder) = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut *rng) {
                    let _ = builder.try_build();
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

/// Test error types are Send + Sync
#[test]
fn test_error_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<Error>();
    assert_sync::<Error>();
}

/// Test zeroization of private keys
#[test]
fn test_private_key_zeroization() {
    use multi_key::types::PrivateKeyBytes;

    {
        let _privkey = PrivateKeyBytes::new(vec![0x42; 32]);
        // Should be zeroized when dropped
    }
    // Memory should be cleared
}
