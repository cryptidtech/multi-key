# CI test budget

The self-hosted `org-runner` Linux runners execute cross-target test jobs
under `qemu-riscv64-static` user-mode emulation. A full `--all-features`
test run of this crate does not fit in the default six-hour job timeout,
so the slowest tests stay behind the `slow-tests` feature and the CI test
jobs enable every other feature. The `Code Lint` step keeps
`--all-features`, so the gated code stays lint-checked.

## Measurement

Each test ran alone under `qemu-riscv64-static` (`RUST_TEST_THREADS=1`,
nightly debug build, `--all-features`) on a 16-core x86_64 workstation.
Serial time is the sum of the single-test times.

- Total serial time of all 255 tests: 17,274 s (4 h 48 m)
- Tests at or over 60 s: 26 tests, 16,368 s (94.8% of the serial time)
- Remaining serial time when those 26 tests are gated: 906 s (15.1 min)
- Doctests (measured the same way): 9 tests, 0.13 s

## Slow tests (60 s or more under emulation)

Already gated behind `slow-tests`: the five SLH-DSA tests, the two XMSS
sign/index tests, and the Classic McEliece tests (the gate sits on the
`tests` module), the x25519+mceliece348864 tests (same), and
`keysplit::tests::roundtrip::roundtrip_slh_dsa`.

Gated by this change (11 tests, 2,486 s under emulation):

| Test | Emulated time (s) |
|------|------------------:|
| `views::sntrup::tests::test_sntrup_seal_open_roundtrip` | 541.9 |
| `keysplit::tests::roundtrip::roundtrip_rsa` | 534.3 |
| `views::lamport_merkle::tests::test_merkle_roundtrip_all_digests_depth1` | 345.5 |
| `keysplit::tests::roundtrip::roundtrip_frodokem` | 209.6 |
| `views::sntrup::tests::test_sntrup_public_key_derivation` | 206.4 |
| `views::lamport_merkle::tests::test_merkle_depth3_sha3_256` | 171.6 |
| `views::x25519_frodokem640::tests::test_640shake_roundtrip` | 141.2 |
| `mk::tests::key_codecs::test_encryption_roundtrip` | 94.8 |
| `views::mayo::tests::test_mayo5_sign_verify_roundtrip` | 89.0 |
| `views::sntrup::tests::test_sntrup_fingerprint` | 82.2 |
| `views::x25519_frodokem640::tests::test_640aes_roundtrip` | 69.1 |

Five of these tests exceed the 1,800 s measurement cap under emulation;
they report at least the cap value and are certainly slower.

## Budget rule

The gated set is every test measured at 60 s or more under emulation. A
test that grows past 60 s under the same measurement belongs behind the
feature again; re-measure with `slow-tests` enabled. The CI job stays
correct as long as the sum of the ungated tests, doctests included, stays
well under the job budget: roughly 906 s today against the 3,600 s
target, with test-thread parallelism and doctests adding margin on the
side of safety.
