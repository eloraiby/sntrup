//! Pure Rust implementation of Streamlined NTRU Prime KEM for all parameter sizes.
//!
//! Streamlined NTRU Prime is a lattice-based, quantum-resistant cryptographic
//! algorithm designed for secure key exchange. This crate supports all six
//! parameter sets: sntrup653, sntrup761, sntrup857, sntrup953, sntrup1013,
//! and sntrup1277.
//!
//! # Usage
//!
//! ```rust
//! use sntrup::{Sntrup761, SntrupKem};
//!
//! let mut rng = rand::rng();
//! let (ek, dk) = Sntrup761::generate_key(&mut rng);
//! let (ct, ss1) = ek.encapsulate(&mut rng);
//! let ss2 = dk.decapsulate(&ct);
//! assert_eq!(ss1, ss2);
//! ```
//!
//! # Security Levels
//!
//! - [`Sntrup653`] / [`sntrup653`]: claimed NIST Category 1 — research/testing only; prefer [`Sntrup761`] or higher for production
//! - [`Sntrup761`] / [`sntrup761`]: claimed NIST Category 2; used by OpenSSH
//! - [`Sntrup857`] / [`sntrup857`]: claimed NIST Category 3
//! - [`Sntrup953`] / [`sntrup953`]: claimed NIST Category 4
//! - [`Sntrup1013`] / [`sntrup1013`]: claimed NIST Category 4
//! - [`Sntrup1277`] / [`sntrup1277`]: claimed NIST Category 5
//!
//! # Sizes (bytes)
//!
//! | Parameter Set | Claimed NIST category | Public Key | Secret Key | Ciphertext | Shared Secret |
//! |---------------|------------|------------|------------|------------|---------------|
//! | sntrup653     | 1          | 994        | 1518       | 897        | 32            |
//! | sntrup761     | 2          | 1158       | 1763       | 1039       | 32            |
//! | sntrup857     | 3          | 1322       | 1999       | 1184       | 32            |
//! | sntrup953     | 4          | 1505       | 2254       | 1349       | 32            |
//! | sntrup1013    | 4          | 1623       | 2417       | 1455       | 32            |
//! | sntrup1277    | 5          | 2067       | 3059       | 1847       | 32            |
//!
//! # Features
//!
//! - `kgen`: key generation (default)
//! - `ecap`: encapsulation (default)
//! - `dcap`: decapsulation (default)
//! - `kem`: implementations of the [`kem`](https://docs.rs/kem) crate's traits,
//!   covering all three operations at once
//! - `serde`: `Serialize`/`Deserialize` for every key and ciphertext type, via
//!   `serdect` for constant-time hex
//! - `js`: WebAssembly randomness for `wasm32-unknown-unknown`
//! - `force-scalar`: compile out every SIMD kernel and use the portable scalar
//!   code paths only
//!
//! # SIMD dispatch
//!
//! Kernel selection happens at run time, from cached CPU-feature probes, so a
//! default `cargo build --release` uses the widest available instruction set
//! without needing `RUSTFLAGS` or `target-cpu=native`. Every SIMD kernel has a
//! scalar counterpart that produces bit-identical output, and the
//! `force-scalar` feature compiles the SIMD paths out entirely.
//!
//! | Target | Selected when | Used for |
//! |--------|---------------|----------|
//! | AVX-512 (F/BW/VL) | probed at run time | divstep inversion, 32 coefficients per step |
//! | AVX2 | probed at run time | NTT multiplication and the remaining x86_64 vector kernels |
//! | NEON | baseline on `aarch64` | all vector kernels |
//! | scalar | no SIMD, or `force-scalar` | everything |
//!
//! Every parameter set uses number-theoretic-transform multiplication on AVX2
//! x86_64 hosts. sntrup653 and sntrup761 use a 3x512 Good decomposition;
//! sntrup857, sntrup953, and sntrup1013 use four strided 512-point tracks with
//! a transformed-variable twist; and sntrup1277 uses a 5x512 Good
//! decomposition. R/q transforms use primes 7681 and 10753 followed by CRT,
//! while bounded R/3 products need only 7681. `aarch64` and non-AVX2 hosts use
//! schoolbook kernels whose output coefficients are contiguous dot products.

mod cpu;
mod ct;
mod error;
#[cfg(feature = "kem")]
pub mod kem;
mod ops;
mod params;
mod r3;
mod rq;
mod scratch;
// The former x86 schoolbook kernels remain compiled only as differential
// oracles for the AVX2 NTT dispatcher.
#[cfg(all(test, target_arch = "x86_64", not(feature = "force-scalar")))]
mod simd;
mod types;
mod utils;
mod wipe;
mod zx;

pub use error::Error;
pub use params::{
    Sntrup653Params, Sntrup761Params, Sntrup857Params, Sntrup953Params, Sntrup1013Params,
    Sntrup1277Params, SntrupParams,
};
pub use types::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret, SntrupKem};

/// sntrup653 KEM (claimed NIST Category 1).
///
/// **Not recommended for production use.** The 653 parameter set provides the
/// lowest security margin. Prefer [`Sntrup761`] or higher for production deployments.
pub type Sntrup653 = SntrupKem<Sntrup653Params>;
/// sntrup761 KEM (claimed NIST Category 2, used by OpenSSH).
pub type Sntrup761 = SntrupKem<Sntrup761Params>;
/// sntrup857 KEM (claimed NIST Category 3).
pub type Sntrup857 = SntrupKem<Sntrup857Params>;
/// sntrup953 KEM (claimed NIST Category 4).
pub type Sntrup953 = SntrupKem<Sntrup953Params>;
/// sntrup1013 KEM (claimed NIST Category 4).
pub type Sntrup1013 = SntrupKem<Sntrup1013Params>;
/// sntrup1277 KEM (claimed NIST Category 5).
pub type Sntrup1277 = SntrupKem<Sntrup1277Params>;

/// Define a per-parameter-set convenience module: size constants (sourced from
/// the `SntrupParams` impl so they cannot drift), type aliases, and free
/// `generate_key` / `generate_key_deterministic` functions.
macro_rules! sntrup_module {
    ($modname:ident, $params:ident, $kem:ident, $doc:expr) => {
        #[doc = $doc]
        pub mod $modname {
            use crate::params::SntrupParams;

            /// Public key size in bytes.
            pub const PUBLIC_KEY_SIZE: usize = crate::$params::PK_BYTES;
            /// Secret key size in bytes.
            pub const SECRET_KEY_SIZE: usize = crate::$params::SK_BYTES;
            /// Ciphertext size in bytes.
            pub const CIPHERTEXT_SIZE: usize = crate::$params::CT_BYTES;
            /// Shared secret size in bytes.
            pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;

            /// Encapsulation key for this parameter set.
            pub type EncapsulationKey = crate::EncapsulationKey<crate::$params>;
            /// Decapsulation key for this parameter set.
            pub type DecapsulationKey = crate::DecapsulationKey<crate::$params>;
            /// Ciphertext for this parameter set.
            pub type Ciphertext = crate::Ciphertext<crate::$params>;
            /// Shared secret for this parameter set.
            pub type SharedSecret = crate::SharedSecret<crate::$params>;

            /// Generate a key pair for this parameter set.
            #[cfg(feature = "kgen")]
            pub fn generate_key(
                rng: &mut impl rand::CryptoRng,
            ) -> (EncapsulationKey, DecapsulationKey) {
                crate::$kem::generate_key(rng)
            }

            /// Generate a key pair deterministically from a 32-byte seed.
            #[cfg(feature = "kgen")]
            pub fn generate_key_deterministic(
                seed: &[u8; 32],
            ) -> (EncapsulationKey, DecapsulationKey) {
                crate::$kem::generate_key_deterministic(seed)
            }
        }
    };
}

sntrup_module!(
    sntrup653,
    Sntrup653Params,
    Sntrup653,
    "sntrup653: claimed NIST Category 1, p=653, q=4621, w=288.\n\n**Not recommended for production use.** Prefer [`sntrup761`] or higher."
);
sntrup_module!(
    sntrup761,
    Sntrup761Params,
    Sntrup761,
    "sntrup761: claimed NIST Category 2, p=761, q=4591, w=286. Used by OpenSSH."
);
sntrup_module!(
    sntrup857,
    Sntrup857Params,
    Sntrup857,
    "sntrup857: claimed NIST Category 3, p=857, q=5167, w=322."
);
sntrup_module!(
    sntrup953,
    Sntrup953Params,
    Sntrup953,
    "sntrup953: claimed NIST Category 4, p=953, q=6343, w=396."
);
sntrup_module!(
    sntrup1013,
    Sntrup1013Params,
    Sntrup1013,
    "sntrup1013: claimed NIST Category 4, p=1013, q=7177, w=448."
);
sntrup_module!(
    sntrup1277,
    Sntrup1277Params,
    Sntrup1277,
    "sntrup1277: claimed NIST Category 5, p=1277, q=7879, w=492."
);
