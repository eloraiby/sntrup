//! Reproduces this repository's independent libntruprime conformance fixtures.
//!
//! The utility supplies identical deterministic byte streams to libntruprime
//! and this crate, compares every generated artifact byte for byte, and then
//! compares valid and invalid decapsulation results. Its stdout is a stable,
//! compact record suitable for comparison with `expected.txt`.

use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha512};
use sntrup::{
    Ciphertext, DecapsulationKey, Sntrup653Params, Sntrup761Params, Sntrup857Params,
    Sntrup953Params, Sntrup1013Params, Sntrup1277Params, SntrupKem, SntrupParams,
};
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

/// ABI of a libntruprime key-generation entry point.
type KeypairFn = unsafe extern "C" fn(*mut u8, *mut u8);
/// ABI of a libntruprime encapsulation entry point.
type EncapsulateFn = unsafe extern "C" fn(*mut u8, *mut u8, *const u8);
/// ABI of a libntruprime decapsulation entry point.
type DecapsulateFn = unsafe extern "C" fn(*mut u8, *const u8, *const u8);

/// Identifies the three C entry points and deterministic stream tag for a set.
#[derive(Clone, Copy, Debug)]
struct ReferenceApi {
    /// Stable parameter-set name printed into the comparison transcript.
    name: &'static str,
    /// Nonzero byte repeated to form this set's key-generation seed.
    stream_id: u8,
    /// libntruprime key-generation function for this parameter set.
    keypair: KeypairFn,
    /// libntruprime encapsulation function for this parameter set.
    encapsulate: EncapsulateFn,
    /// libntruprime decapsulation function for this parameter set.
    decapsulate: DecapsulateFn,
}

unsafe extern "C" {
    /// Generates an sntrup653 key pair with the supplied `randombytes` symbol.
    fn ntruprime_kem_sntrup653_keypair(public_key: *mut u8, private_key: *mut u8);
    /// Encapsulates to an sntrup653 public key.
    fn ntruprime_kem_sntrup653_enc(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    );
    /// Decapsulates an sntrup653 ciphertext.
    fn ntruprime_kem_sntrup653_dec(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        private_key: *const u8,
    );

    /// Generates an sntrup761 key pair with the supplied `randombytes` symbol.
    fn ntruprime_kem_sntrup761_keypair(public_key: *mut u8, private_key: *mut u8);
    /// Encapsulates to an sntrup761 public key.
    fn ntruprime_kem_sntrup761_enc(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    );
    /// Decapsulates an sntrup761 ciphertext.
    fn ntruprime_kem_sntrup761_dec(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        private_key: *const u8,
    );

    /// Generates an sntrup857 key pair with the supplied `randombytes` symbol.
    fn ntruprime_kem_sntrup857_keypair(public_key: *mut u8, private_key: *mut u8);
    /// Encapsulates to an sntrup857 public key.
    fn ntruprime_kem_sntrup857_enc(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    );
    /// Decapsulates an sntrup857 ciphertext.
    fn ntruprime_kem_sntrup857_dec(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        private_key: *const u8,
    );

    /// Generates an sntrup953 key pair with the supplied `randombytes` symbol.
    fn ntruprime_kem_sntrup953_keypair(public_key: *mut u8, private_key: *mut u8);
    /// Encapsulates to an sntrup953 public key.
    fn ntruprime_kem_sntrup953_enc(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    );
    /// Decapsulates an sntrup953 ciphertext.
    fn ntruprime_kem_sntrup953_dec(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        private_key: *const u8,
    );

    /// Generates an sntrup1013 key pair with the supplied `randombytes` symbol.
    fn ntruprime_kem_sntrup1013_keypair(public_key: *mut u8, private_key: *mut u8);
    /// Encapsulates to an sntrup1013 public key.
    fn ntruprime_kem_sntrup1013_enc(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    );
    /// Decapsulates an sntrup1013 ciphertext.
    fn ntruprime_kem_sntrup1013_dec(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        private_key: *const u8,
    );

    /// Generates an sntrup1277 key pair with the supplied `randombytes` symbol.
    fn ntruprime_kem_sntrup1277_keypair(public_key: *mut u8, private_key: *mut u8);
    /// Encapsulates to an sntrup1277 public key.
    fn ntruprime_kem_sntrup1277_enc(
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    );
    /// Decapsulates an sntrup1277 ciphertext.
    fn ntruprime_kem_sntrup1277_dec(
        shared_secret: *mut u8,
        ciphertext: *const u8,
        private_key: *const u8,
    );
}

/// Serial deterministic generator read by libntruprime's `randombytes` calls.
///
/// libntruprime invokes a process-global symbol, so the reproduction utility
/// deliberately runs one transcript at a time and protects that state against
/// accidental concurrent access.
static REFERENCE_RNG: Mutex<Option<rand_chacha::ChaCha20Rng>> = Mutex::new(None);

/// Acquires the C reference generator even if an earlier assertion poisoned it.
fn reference_rng() -> MutexGuard<'static, Option<rand_chacha::ChaCha20Rng>> {
    // A poisoned lock is still safe to inspect here: this single-threaded
    // verification process will fail its next invariant instead of continuing
    // cryptographic service with ambiguous state.
    REFERENCE_RNG
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Starts a fresh deterministic byte stream for one C operation.
fn reset_reference_rng(seed: [u8; 32]) {
    // Replacing the generator drops a ChaCha core whose dependency-provided
    // zeroize-on-drop implementation clears its key and buffered output.
    *reference_rng() = Some(rand_chacha::ChaCha20Rng::from_seed(seed));
}

/// Supplies deterministic bytes to the linked libntruprime implementation.
///
/// # Safety contract
///
/// libntruprime must pass a non-null writable region of exactly `length` bytes
/// and must call this function only after [`reset_reference_rng`]. The pinned C
/// implementation satisfies those requirements during key generation and
/// encapsulation.
#[unsafe(no_mangle)]
extern "C" fn randombytes(output: *mut core::ffi::c_void, length: i64) {
    // Reject impossible or unrepresentable sizes before constructing a slice
    // from the foreign pointer.
    let length = usize::try_from(length)
        .unwrap_or_else(|_| panic!("libntruprime requested a negative byte count"));
    assert!(
        !output.is_null(),
        "libntruprime passed a null randombytes destination"
    );

    // SAFETY: the C implementation owns a writable `length`-byte destination
    // for this callback, as required by the contract documented above.
    let output = unsafe { core::slice::from_raw_parts_mut(output.cast::<u8>(), length) };
    let mut generator = reference_rng();
    let generator = generator
        .as_mut()
        .unwrap_or_else(|| panic!("reference RNG must be initialized before a C operation"));
    generator.fill_bytes(output);
}

/// Computes a lowercase SHA-512 fingerprint of one byte sequence.
fn sha512_hex(bytes: &[u8]) -> String {
    // Fingerprints keep public transcript records compact without omitting any
    // artifact from the byte-for-byte comparisons performed before printing.
    hex::encode(Sha512::digest(bytes))
}

/// Computes the compact fixture used by `tests/reference_vectors.rs`.
fn transcript_digest(
    public_key: &[u8],
    private_key: &[u8],
    ciphertext: &[u8],
    shared_secret: &[u8],
) -> String {
    // Preserve the test fixture's exact, delimiter-free concatenation order.
    let mut digest = Sha512::new();
    digest.update(public_key);
    digest.update(private_key);
    digest.update(ciphertext);
    digest.update(shared_secret);
    hex::encode(digest.finalize())
}

/// Decapsulates and compares one fixed-size ciphertext with both implementations.
fn compare_decapsulation<P: SntrupParams>(
    api: ReferenceApi,
    private_key: &[u8],
    rust_key: &DecapsulationKey<P>,
    label: &str,
    ciphertext: &[u8],
) {
    // Keep the independent C result in a zeroizing wrapper because every
    // result, including an implicit-rejection value, is key material.
    let mut reference_secret = Zeroizing::new([0u8; 32]);
    // SAFETY: all slices have the fixed sizes required by this parameter set,
    // and `api` selects the matching C implementation.
    unsafe {
        (api.decapsulate)(
            reference_secret.as_mut_ptr(),
            ciphertext.as_ptr(),
            private_key.as_ptr(),
        );
    }

    // Import only the public ciphertext. Fixed-length arbitrary contents are
    // intentionally accepted so implicit rejection remains observable here.
    let rust_ciphertext = Ciphertext::<P>::try_from(ciphertext.to_vec()).unwrap_or_else(|error| {
        panic!("the reproduction harness supplied an invalid ciphertext length: {error}")
    });
    let rust_secret = rust_key.decapsulate(&rust_ciphertext);
    assert_eq!(
        rust_secret.as_ref(),
        reference_secret.as_slice(),
        "{} {label} decapsulation",
        api.name
    );
    println!(
        "{} {label} {}",
        api.name,
        hex::encode(reference_secret.as_slice())
    );
}

/// Reproduces generation and rejection fixtures for one parameter set.
fn compare_parameter_set<P: SntrupParams>(api: ReferenceApi) {
    // Give C and Rust independent ChaCha instances seeded identically. This
    // compares the standardized algorithms, not the crate's domain-separated
    // deterministic-key convenience method.
    let key_seed = [api.stream_id; 32];
    reset_reference_rng(key_seed);
    let mut reference_public_key = vec![0u8; P::PK_BYTES];
    let mut reference_private_key = Zeroizing::new(vec![0u8; P::SK_BYTES]);
    // SAFETY: both destinations have exactly the sizes required by the C entry
    // point selected for this generic parameter type.
    unsafe {
        (api.keypair)(
            reference_public_key.as_mut_ptr(),
            reference_private_key.as_mut_ptr(),
        );
    }

    let mut rust_key_rng = rand_chacha::ChaCha20Rng::from_seed(key_seed);
    let (rust_public_key, rust_private_key) = SntrupKem::<P>::generate_key(&mut rust_key_rng);
    assert_eq!(
        rust_public_key.as_ref(),
        reference_public_key,
        "{} public key",
        api.name
    );
    assert_eq!(
        rust_private_key.as_ref(),
        reference_private_key.as_slice(),
        "{} private key",
        api.name
    );

    // Repeat the process for encapsulation with a distinct, documented stream.
    let encapsulation_seed = [api.stream_id ^ 0x80; 32];
    reset_reference_rng(encapsulation_seed);
    let mut reference_ciphertext = vec![0u8; P::CT_BYTES];
    let mut reference_shared_secret = Zeroizing::new([0u8; 32]);
    // SAFETY: the output buffers and public key have the exact sizes required
    // by the matching C encapsulation entry point.
    unsafe {
        (api.encapsulate)(
            reference_ciphertext.as_mut_ptr(),
            reference_shared_secret.as_mut_ptr(),
            reference_public_key.as_ptr(),
        );
    }

    let mut rust_encapsulation_rng = rand_chacha::ChaCha20Rng::from_seed(encapsulation_seed);
    let (rust_ciphertext, rust_shared_secret) =
        rust_public_key.encapsulate(&mut rust_encapsulation_rng);
    assert_eq!(
        rust_ciphertext.as_ref(),
        reference_ciphertext,
        "{} ciphertext",
        api.name
    );
    assert_eq!(
        rust_shared_secret.as_ref(),
        reference_shared_secret.as_slice(),
        "{} encapsulated shared secret",
        api.name
    );

    // Print individual artifact fingerprints so a future mismatch identifies
    // the first divergent stage, followed by the exact compact test fixture.
    println!(
        "{} public-key-sha512 {}",
        api.name,
        sha512_hex(&reference_public_key)
    );
    println!(
        "{} private-key-sha512 {}",
        api.name,
        sha512_hex(reference_private_key.as_slice())
    );
    println!(
        "{} ciphertext-sha512 {}",
        api.name,
        sha512_hex(&reference_ciphertext)
    );
    println!(
        "{} encapsulated {}",
        api.name,
        hex::encode(reference_shared_secret.as_slice())
    );
    println!(
        "{} transcript-sha512 {}",
        api.name,
        transcript_digest(
            &reference_public_key,
            reference_private_key.as_slice(),
            &reference_ciphertext,
            reference_shared_secret.as_slice(),
        )
    );

    // Exercise exact valid decapsulation before constructing five fixed invalid
    // inputs that cover confirmation, rounded encoding, and extreme byte forms.
    compare_decapsulation::<P>(
        api,
        reference_private_key.as_slice(),
        &rust_private_key,
        "valid",
        &reference_ciphertext,
    );

    let mut changed = reference_ciphertext.clone();
    changed[P::CT_BYTES - 1] ^= 1;
    compare_decapsulation::<P>(
        api,
        reference_private_key.as_slice(),
        &rust_private_key,
        "confirmation-bit",
        &changed,
    );

    changed.copy_from_slice(&reference_ciphertext);
    changed[0] ^= 1;
    compare_decapsulation::<P>(
        api,
        reference_private_key.as_slice(),
        &rust_private_key,
        "rounded-bit",
        &changed,
    );

    compare_decapsulation::<P>(
        api,
        reference_private_key.as_slice(),
        &rust_private_key,
        "all-zero",
        &vec![0u8; P::CT_BYTES],
    );
    compare_decapsulation::<P>(
        api,
        reference_private_key.as_slice(),
        &rust_private_key,
        "all-ff",
        &vec![0xffu8; P::CT_BYTES],
    );

    changed.copy_from_slice(&reference_ciphertext);
    changed[P::CT_BYTES - 33] ^= 0x80;
    compare_decapsulation::<P>(
        api,
        reference_private_key.as_slice(),
        &rust_private_key,
        "rounded-boundary",
        &changed,
    );
}

/// Runs the complete six-parameter independent comparison in fixture order.
fn main() {
    // Explicit calls preserve the compile-time association between each Rust
    // parameter type and its corresponding libntruprime symbols.
    compare_parameter_set::<Sntrup653Params>(ReferenceApi {
        name: "sntrup653",
        stream_id: 0x11,
        keypair: ntruprime_kem_sntrup653_keypair,
        encapsulate: ntruprime_kem_sntrup653_enc,
        decapsulate: ntruprime_kem_sntrup653_dec,
    });
    compare_parameter_set::<Sntrup761Params>(ReferenceApi {
        name: "sntrup761",
        stream_id: 0x22,
        keypair: ntruprime_kem_sntrup761_keypair,
        encapsulate: ntruprime_kem_sntrup761_enc,
        decapsulate: ntruprime_kem_sntrup761_dec,
    });
    compare_parameter_set::<Sntrup857Params>(ReferenceApi {
        name: "sntrup857",
        stream_id: 0x33,
        keypair: ntruprime_kem_sntrup857_keypair,
        encapsulate: ntruprime_kem_sntrup857_enc,
        decapsulate: ntruprime_kem_sntrup857_dec,
    });
    compare_parameter_set::<Sntrup953Params>(ReferenceApi {
        name: "sntrup953",
        stream_id: 0x44,
        keypair: ntruprime_kem_sntrup953_keypair,
        encapsulate: ntruprime_kem_sntrup953_enc,
        decapsulate: ntruprime_kem_sntrup953_dec,
    });
    compare_parameter_set::<Sntrup1013Params>(ReferenceApi {
        name: "sntrup1013",
        stream_id: 0x55,
        keypair: ntruprime_kem_sntrup1013_keypair,
        encapsulate: ntruprime_kem_sntrup1013_enc,
        decapsulate: ntruprime_kem_sntrup1013_dec,
    });
    compare_parameter_set::<Sntrup1277Params>(ReferenceApi {
        name: "sntrup1277",
        stream_id: 0x66,
        keypair: ntruprime_kem_sntrup1277_keypair,
        encapsulate: ntruprime_kem_sntrup1277_enc,
        decapsulate: ntruprime_kem_sntrup1277_dec,
    });
}
