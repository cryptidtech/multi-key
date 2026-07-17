// SPDX-License-Identifier: Apache-2.0
//! Performance benchmarks for multi-key
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use multi_codec::Codec;
use multi_key::{Builder, Multikey};
use std::hint::black_box;

/// Benchmark key generation
fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    let mut rng = rand::rng();
    let algorithms = vec![
        ("Ed25519", Codec::Ed25519Priv),
        ("Secp256k1", Codec::Secp256K1Priv),
    ];

    for (name, codec) in algorithms {
        group.bench_with_input(BenchmarkId::new("generate", name), &codec, |b, &codec| {
            b.iter(|| {
                Builder::new_from_random_bytes(black_box(codec), &mut rng)
                    .unwrap()
                    .try_build()
            })
        });
    }

    group.finish();
}

/// Benchmark encoding
fn bench_encoding(c: &mut Criterion) {
    let mut rng = rand::rng();
    let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
        .unwrap()
        .try_build()
        .unwrap();

    c.bench_function("multikey_to_bytes", |b| {
        b.iter(|| {
            let _bytes: Vec<u8> = black_box(mk.clone()).into();
        })
    });
}

/// Benchmark decoding
fn bench_decoding(c: &mut Criterion) {
    let mut rng = rand::rng();
    let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
        .unwrap()
        .try_build()
        .unwrap();
    let bytes: Vec<u8> = mk.into();

    c.bench_function("multikey_from_bytes", |b| {
        b.iter(|| Multikey::try_from(black_box(bytes.as_ref())))
    });
}

/// Benchmark roundtrip
fn bench_roundtrip(c: &mut Criterion) {
    let mut rng = rand::rng();

    c.bench_function("roundtrip_ed25519", |b| {
        b.iter(|| {
            let mk1 = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
                .unwrap()
                .try_build()
                .unwrap();
            let bytes: Vec<u8> = mk1.into();
            let _mk2 = Multikey::try_from(bytes.as_ref()).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_encoding,
    bench_decoding,
    bench_roundtrip
);

criterion_main!(benches);
