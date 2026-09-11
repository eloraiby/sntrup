# sntrup
[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/mikelodder7/sntrup/actions/workflows/sntrup.yml/badge.svg)
![MSRV][msrv-image]

A pure-Rust implementation of [Streamlined NTRU Prime](https://ntruprime.cr.yp.to/) for all parameter sizes.

NTRU Prime is a lattice-based cryptosystem aiming to improve the security of lattice schemes at minimal cost. It is thought to be resistant to quantum computing advances, in particular Shor's algorithm. It made it to NIST final round but was not selected for finalization.

Please read the [warnings](#warnings) before use.

The algorithm was authored by Daniel J. Bernstein, Chitchanok Chuengsatiansup, Tanja Lange & Christine van Vredendaal. This implementation follows the [NTRU Prime Round 3 specification](https://ntruprime.cr.yp.to/nist/ntruprime-20201007.pdf). It is checked against the current upstream `libntruprime` implementation for all six parameter sets and against the legacy sntrup761 vectors that preceded [RFC 9941](https://www.rfc-editor.org/rfc/rfc9941.html). RFC 9941 specifies the hybrid `sntrup761x25519-sha512` SSH construction as an Informational RFC; it is not a standalone standard for all six KEMs.

## Parameter Sets

| Parameter Set | Claimed NIST category | P    | Q    | W   | Public Key | Secret Key | Ciphertext | Shared Secret |
|---------------|:----------:|-----:|-----:|----:|-----------:|-----------:|-----------:|--------------:|
| sntrup653     | 1          |  653 | 4621 | 288 |        994 |       1518 |        897 |            32 |
| sntrup761     | 2          |  761 | 4591 | 286 |       1158 |       1763 |       1039 |            32 |
| sntrup857     | 3          |  857 | 5167 | 322 |       1322 |       1999 |       1184 |            32 |
| sntrup953     | 4          |  953 | 6343 | 396 |       1505 |       2254 |       1349 |            32 |
| sntrup1013    | 4          | 1013 | 7177 | 448 |       1623 |       2417 |       1455 |            32 |
| sntrup1277    | 5          | 1277 | 7879 | 492 |       2067 |       3059 |       1847 |            32 |

All key and ciphertext sizes are in bytes. Key imports enforce canonical encodings; private-key imports also verify cache consistency, fixed weight, and polynomial coherence. Ciphertext imports intentionally enforce only the fixed length so invalid ciphertexts reach implicit rejection without creating a parser oracle.

> **Note:** sntrup653 (claimed NIST Category 1) is recommended for research and testing only. Prefer sntrup761 or higher for production use.

## Features

- Pure Rust and dependency-minimal; the current implementation requires `std`
- All six parameter sizes: sntrup653, sntrup761, sntrup857, sntrup953, sntrup1013, sntrup1277
- Targets IND-CCA2 security with implicit rejection
- Data-independent decapsulation design (branchless sort, constant-time comparison and selection), subject to the platform and compiler caveats in [SECURITY.md](SECURITY.md)
- SIMD acceleration with automatic run-time detection: AVX-512 and AVX2 on x86_64, NEON on aarch64
- Optional `serde` support via the `serde` feature
- Deterministic key generation from a 32-byte seed

### Feature Flags

The KEM API is split into three default features so downstream crates can pull in only what they need:

| Feature | Default | Description |
|---------|:-------:|-------------|
| `kgen`  | **yes** | Key generation: `SntrupKem::generate_key`, `SntrupKem::generate_key_deterministic` |
| `ecap`  | **yes** | Encapsulation: `EncapsulationKey::encapsulate` |
| `dcap`  | **yes** | Decapsulation: `DecapsulationKey::decapsulate` |
| `force-scalar` | no | Compile out every SIMD kernel and use the portable scalar code paths only |
| `kem`   | no | Implements the [`kem`](https://docs.rs/kem) crate's traits (`Encapsulate`, `Decapsulate`, `Kem`, ...) so this crate can be used generically alongside other KEMs. See [`sntrup::kem`](src/kem.rs) and `examples/kem_traits.rs`. |
| `serde` | no | Enables `Serialize`/`Deserialize` for all key and ciphertext types (via `serdect` for constant-time hex encoding) |
| `js`    | no | Enables WebAssembly support for `wasm32-unknown-unknown` by configuring `getrandom` to use JavaScript's `crypto.getRandomValues()` |

To use only a subset of the KEM API, disable defaults and pick the features you need:

```toml
[dependencies]
# Decapsulation only (e.g. a receiver that never generates keys or encapsulates)
sntrup = { version = "0.4", default-features = false, features = ["dcap"] }
```

## Usage

### Key generation

```rust
use sntrup::{Sntrup761, SntrupKem};

let mut rng = rand::rng();
let (encapsulation_key, decapsulation_key) = Sntrup761::generate_key(&mut rng);
```

All six parameter sets are available as type aliases:

```rust
use sntrup::{Sntrup653, Sntrup761, Sntrup857, Sntrup953, Sntrup1013, Sntrup1277, SntrupKem};

let mut rng = rand::rng();
let (ek_653, dk_653) = Sntrup653::generate_key(&mut rng);
let (ek_761, dk_761) = Sntrup761::generate_key(&mut rng);
let (ek_857, dk_857) = Sntrup857::generate_key(&mut rng);
let (ek_953, dk_953) = Sntrup953::generate_key(&mut rng);
let (ek_1013, dk_1013) = Sntrup1013::generate_key(&mut rng);
let (ek_1277, dk_1277) = Sntrup1277::generate_key(&mut rng);
```

Or use the convenience modules with parameter-specific types:

```rust
let mut rng = rand::rng();
let (ek, dk) = sntrup::sntrup761::generate_key(&mut rng);
```

### Encapsulation

The sender uses the encapsulation (public) key to produce a ciphertext and shared secret:

```rust
use sntrup::{Sntrup761, SntrupKem};

let mut rng = rand::rng();
let (encapsulation_key, decapsulation_key) = Sntrup761::generate_key(&mut rng);

// Sender side
let (ciphertext, shared_secret_sender) = encapsulation_key.encapsulate(&mut rng);
```

### Decapsulation

The receiver uses the decapsulation (secret) key and the ciphertext to recover the shared secret:

```rust
use sntrup::{Sntrup761, SntrupKem};

let mut rng = rand::rng();
let (encapsulation_key, decapsulation_key) = Sntrup761::generate_key(&mut rng);
let (ciphertext, shared_secret_sender) = encapsulation_key.encapsulate(&mut rng);

// Receiver side — implicit rejection: always returns a key
let shared_secret_receiver = decapsulation_key.decapsulate(&ciphertext);

assert_eq!(shared_secret_sender, shared_secret_receiver);
```

### Deterministic key generation

Derive the same keypair from a 32-byte seed:

```rust
use sntrup::{Sntrup761, SntrupKem};

let seed = [0x42u8; 32]; // must come from a cryptographically secure source
let (ek1, dk1) = Sntrup761::generate_key_deterministic(&seed);
let (ek2, dk2) = Sntrup761::generate_key_deterministic(&seed);
assert_eq!(ek1, ek2);
assert_eq!(dk1, dk2);
```

This deterministic API is a crate-specific, versioned SHA-512 derivation
followed by ChaCha20 expansion. The derivation includes the parameter-set name,
so reusing a caller seed across parameter sets does not reuse the same random
stream. It is useful for reproducible applications and tests, but it is not the
NIST KAT DRBG interface and cannot consume NIST `.rsp` seed fields directly.

### Serialization with serde

Enable the `serde` feature:

```toml
sntrup = { version = "0.4", features = ["serde"] }
```

Keys and ciphertexts serialize to hex in human-readable formats (JSON) and raw bytes in binary formats (postcard, bincode):

```rust,ignore
use sntrup::{Sntrup761, SntrupKem, EncapsulationKey, Sntrup761Params};

let mut rng = rand::rng();
let (ek, dk) = Sntrup761::generate_key(&mut rng);
let json = serde_json::to_string(&ek).unwrap();
let ek2: EncapsulationKey<Sntrup761Params> = serde_json::from_str(&json).unwrap();
assert_eq!(ek, ek2);
```

### Byte conversions

All types support `AsRef<[u8]>` and `TryFrom<&[u8]>`:

```rust
use sntrup::{Sntrup761, SntrupKem, EncapsulationKey, Sntrup761Params};

let mut rng = rand::rng();
let (ek, dk) = Sntrup761::generate_key(&mut rng);

// Serialize to bytes
let ek_bytes: &[u8] = ek.as_ref();

// Deserialize from bytes (validates size and canonical key encoding)
let ek2 = EncapsulationKey::<Sntrup761Params>::try_from(ek_bytes).unwrap();
assert_eq!(ek, ek2);
```

### `kem` crate integration

With the `kem` feature enabled, the [`kem`](https://docs.rs/kem) module implements that crate's
traits for every parameter set, so Streamlined NTRU Prime can be used in generic code alongside
other KEMs. The traits and the parameter-set marker types are re-exported there, so no direct
dependency on the `kem` crate is needed:

```rust
# #[cfg(feature = "kem")] {
use sntrup::kem::{Decapsulate, Encapsulate, Kem, Sntrup761Params};
use rand::SeedableRng;
use rand::rngs::{StdRng, SysRng};

let mut rng = StdRng::try_from_rng(&mut SysRng).expect("OS randomness");

let (dk, ek) = Sntrup761Params::generate_keypair_from_rng(&mut rng);
let (ct, sent) = ek.encapsulate_with_rng(&mut rng);
assert_eq!(dk.decapsulate(&ct), sent);
# }
```

Run `cargo run --release --example kem_traits --features kem` for KEM-generic code and key
export.

## WebAssembly

To compile for `wasm32-unknown-unknown`, enable the `js` feature so that `getrandom` uses JavaScript's `crypto.getRandomValues()` for randomness:

```toml
[dependencies]
sntrup = { version = "0.4", features = ["js"] }
```

Install the target and build:

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --features js
```

For `wasm32-wasi` (or `wasm32-wasip1`), the `js` feature is **not** needed since WASI provides its own random source.

## Security Properties

- **IND-CCA2 security** via implicit rejection: decapsulation always returns a shared key. On failure, a pseudorandom key is derived from secret randomness (`rho`), making it indistinguishable from a valid key to an attacker.
- **Hash domain separation**: all hashes use prefix bytes (following the NTRU Prime specification).
- **Side-channel-conscious operations**: branchless sorting (djbsort), fixed-schedule weight checks, constant-time ciphertext comparison, and constant-time selection in decapsulation. This is an implementation intent, not a universal timing guarantee; see [SECURITY.md](SECURITY.md).
- **Zeroization**: private-key and shared-secret wrappers erase their allocations on drop, and secret-derived internal workspaces are erased before release. Copies exported by callers remain caller-owned.
- **Conformance tests**: compact full-transcript fixtures pin byte-for-byte agreement with `libntruprime` for every parameter set, while the original sntrup761 draft vectors remain checked separately.

## Warnings

#### Implementation

This branch incorporates an implementation security audit and its memory-safety, validation, dependency, and test-coverage fixes. It has not undergone an independent third-party cryptographic audit or formal side-channel validation. Review [SECURITY.md](SECURITY.md) before production deployment.

Secret-derived heap temporaries (multiply scratch, Euclidean-inversion state,
sampling randomness, hash intermediates, and deterministic ChaCha20 state) are
wiped before being freed. Remaining erasure and timing limitations are
documented in [SECURITY.md](SECURITY.md).

#### Algorithm

Streamlined NTRU Prime was first published in 2016. The algorithm still requires careful security review. Please see [here](https://ntruprime.cr.yp.to/warnings.html) for further warnings from the authors regarding NTRU Prime and lattice-based encryption schemes.

## Performance

`cargo bench` runs this crate's own Criterion suite (`benches/mod.rs`) across all six parameter
sets. A separate standalone harness at [`benches/comparison`](benches/comparison) benchmarks
sntrup761 — the one parameter set with independent implementations to compare against — against
`pqcrypto-ntruprime` (PQClean's C reference) and `oqs` (liboqs):

```sh
cargo bench --manifest-path benches/comparison/Cargo.toml
```

This crate is faster than both C references on every operation, on both
architectures, while also zeroizing every secret-derived scratch buffer — which neither C
reference does.

On x86_64 (AMD Ryzen AI 9 HX 370, Zen 5), sntrup761, against liboqs's AVX2 build:

| Operation | sntrup | liboqs | PQClean |
|-----------|-------:|-------:|--------:|
| keypair | 106.6 µs | 107.9 µs (0.99x) | 4545.7 µs (42.7x) |
| encapsulate | 10.5 µs | 11.5 µs (0.91x) | 239.1 µs (22.9x) |
| decapsulate | 8.4 µs | 8.4 µs (1.00x) | 607.0 µs (72.6x) |

On aarch64 (Apple M2 Max), sntrup761, against their portable C builds: keypair 684 µs
(2.7x), encapsulate 37.0 µs (1.40x), decapsulate 77.1 µs (1.19x).

Two things drive the x86_64 numbers. Key generation runs the Bernstein–Yang divstep inversion
through **AVX-512**, 32 coefficients per step — neither PQClean nor liboqs has a 512-bit path
for this KEM. Encapsulation and decapsulation use number-theoretic-transform multiplication
on every AVX2 parameter set. sntrup653 and sntrup761 use a 3x512 Good decomposition;
sntrup857, sntrup953, and sntrup1013 use four strided 512-point tracks with a transformed-track
twist; and sntrup1277 uses a 5x512 Good decomposition. R/q uses the primes 7681 and 10753 with
CRT recombination, while bounded R/3 products need only 7681. On aarch64 and x86_64 without
AVX2, a schoolbook kernel computes each output coefficient as a contiguous dot product spread
across independent widening multiply-accumulate chains.

See [`benches/comparison/RESULTS.md`](benches/comparison/RESULTS.md) for the full
investigation narrative — every landed optimization with its measurement, and the measured
dead ends — plus machine and build details.

**A SIMD-testing gotcha every contributor should read:** `--all-features` enables
`force-scalar`, which silently compiles the SIMD kernels out of the test binary. The permanent
kernel-vs-scalar differential tests in `src/rq.rs` and `src/r3.rs` only exercise SIMD when
built with a feature set that leaves `force-scalar` off, e.g. `--features kem,serde`.

# License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/sntrup.svg
[crate-link]: https://crates.io/crates/sntrup
[docs-image]: https://docs.rs/sntrup/badge.svg
[docs-link]: https://docs.rs/sntrup/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[downloads-image]: https://img.shields.io/crates/d/sntrup.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.95+-blue.svg
