//! Internal KEM operations for Streamlined NTRU Prime.
//!
//! Top-level keygen/encaps/decaps functions that delegate to `utils` for
//! the core cryptographic operations.

use crate::params::SntrupParameters;
use crate::wipe::SecretBuffer;
use crate::{r3, utils, zx};
use rand::CryptoRng;

/// Copies a fixed-size session key into its owned API representation and
/// clears the temporary array before returning.
///
/// Keeping this transition in one helper prevents encapsulation and
/// decapsulation from silently leaving identical key bytes in their stack
/// frames after converting to `Vec<u8>`.
fn session_key_to_vec(key: [u8; 32]) -> Vec<u8> {
    let key = SecretBuffer::new(key);
    key.to_vec()
}

/// Generate a Streamlined NTRU Prime key pair.
///
/// Returns `(pk_bytes, sk_bytes)` as `Vec<u8>`.
///
/// The retry count depends on how many random `g` candidates are singular. It
/// is therefore not a constant-time operation; see `SECURITY.md`.
#[cfg(feature = "kgen")]
pub(crate) fn keygen(params: &SntrupParameters, rng: &mut impl CryptoRng) -> (Vec<u8>, Vec<u8>) {
    let p = params.p;

    // Generate g and its reciprocal in R3
    let mut g = SecretBuffer::new(vec![0i8; p]);
    let gr = loop {
        zx::random::random_small(&mut g, rng);
        let (mask, candidate) = r3::reciprocal(&g, p);
        let candidate = SecretBuffer::new(candidate);
        if mask == 0 {
            break candidate;
        }
        // A rejected reciprocal is derived from the candidate secret. Its drop
        // guard erases it before the retry begins, including during unwinding.
    };

    // Generate f with Hamming weight w
    let mut f = SecretBuffer::new(vec![0i8; p]);
    zx::random::random_tsmall(&mut f, p, params.w, rng);

    // Generate random rho for implicit rejection (raw random bytes, per PQClean)
    let mut rho = SecretBuffer::new(vec![0u8; params.small_encode_size]);
    rng.fill_bytes(&mut rho);

    let result = utils::derive_key(&f, &g, &gr, &rho, params);
    // The four guards erase their buffers together on normal return and on
    // panic unwinding from caller-supplied random generators or arithmetic.
    result
}

/// Encapsulate with a public key, supplied pre-decoded.
///
/// `h` is the decoded public-key polynomial and `pk_hash` is Hash4(pk); both are
/// per-key constants the caller caches so repeated encapsulations skip re-deriving
/// them.
///
/// Returns `(ciphertext_bytes, shared_secret_bytes)`.
#[cfg(feature = "ecap")]
pub(crate) fn encaps(
    h: &[i16],
    pk_hash: &[u8; 32],
    params: &SntrupParameters,
    rng: &mut impl CryptoRng,
) -> (Vec<u8>, Vec<u8>) {
    let p = params.p;

    // Generate random r with Hamming weight w
    let mut r = SecretBuffer::new(vec![0i8; p]);
    zx::random::random_tsmall(&mut r, p, params.w, rng);

    let (ct, ss) = utils::create_cipher(&r, h, pk_hash, params);
    // The guard erases `r` even if random generation or encryption unwinds.
    (ct, session_key_to_vec(ss))
}

/// Decapsulate with a secret key.
///
/// Returns shared secret bytes.
#[cfg(feature = "dcap")]
pub(crate) fn decaps(sk: &[u8], h: &[i16], ct: &[u8], params: &SntrupParameters) -> Vec<u8> {
    let ss = utils::decapsulate_inner(ct, sk, h, params);
    session_key_to_vec(ss)
}
