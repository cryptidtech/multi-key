# CI test budget

The self-hosted Linux runners run the cross-target test jobs under
`qemu-aarch64-static` and `qemu-riscv64-static` user-mode emulation. Two
features hold out the tests that push an emulated test run past its test
budget: `slow-tests-aarch64` on the aarch64 target and `slow-tests-riscv`
on the riscv64gc target. A third feature, `slow-tests`, holds out the
tests the native test run needs held out. The test jobs enable every
other feature. The `Code Lint` step and the `Check` and `Build` steps
keep `--all-features`, so the gated code stays compile-checked.

## Measurement

Each test ran alone under the matching `qemu-*-static` emulator
(`RUST_TEST_THREADS=1`, nightly debug build, `--all-features`) on a
16-core x86_64 workstation. Serial time is the sum of the single-test
times.

- Total serial time of all 255 tests of the riscv64gc measurement:
  17,274 s (4 h 48 m)
- riscv64gc tests at or over 60 s: 26 tests, 16,368 s (94.8% of the serial
  time)
- The `slow-tests` gate holds 18 tests. The native test run needs them
  held out to stay on budget.
- The `slow-tests-riscv` gate holds 11 tests. Their emulated serial time
  adds to 2,486 s (the table below).
- Remaining riscv64gc serial time when the 26 tests are gated: 906 s
  (15.1 min)
- Doctests (measured the same way): 9 tests, 0.13 s
- One full riscv64gc run with the CI feature list and `slow-tests-riscv`
  enabled took 291.7 s and passed every test.
- The aarch64 run needs no held-out test today. A full run with the CI
  feature list measured 21.6 s and 20.3 s back to back. The slowest
  single test measured 20.7 s. `slow-tests-aarch64` is the hold-out
  point for a future slow aarch64 test.
- The native test run with the same feature list measured 22.9 s.

## Slow tests (60 s or more under emulation)

Behind `slow-tests`: the SLH-DSA tests in `mk` and `keysplit`, the two
XMSS sign and index tests, and the Classic McEliece tests and the
x25519+mceliece348864 tests (the gate sits on their tests modules).

Behind `slow-tests-riscv` (11 tests, 2,486 s serial under emulation):

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

Five of the tests behind `slow-tests` exceed the 1,800 s measurement cap
under emulation. They report the cap value as a lower bound, so their
true serial time is larger. None of those tests appears in the table
above.

## Budget rule

The wall clock of one complete run with the CI feature list is the budget
measure. The measured budgets: 20-22 s on aarch64 and 76-86 s on
riscv64gc against a 300 s target. A test that grows past 60 s in a
single-test measurement on that target belongs behind that target's
feature again. Re-measure with that gate enabled. The CI job stays
correct as long as the sum of the ungated tests, doctests included, stays
well under the job budget.
