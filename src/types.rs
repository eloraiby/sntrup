//! Generic Streamlined NTRU Prime types parameterized by parameter set.

use crate::error::Error;
use crate::params::SntrupParams;
use crate::wipe::SecretBuffer;
use core::marker::PhantomData;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Streamlined NTRU Prime encapsulation key (public key).
///
/// Byte imports reject non-canonical variable-radix encodings. Keys generated
/// by this crate and conforming implementations are canonical by construction.
#[derive(Clone)]
pub struct EncapsulationKey<P: SntrupParams> {
    bytes: Vec<u8>,
    /// Decoded public-key polynomial and Hash4(pk), cached on first encapsulation.
    ///
    /// Encapsulation re-derives both on every call otherwise — repeated work that is
    /// identical per key (~10% of the operation). Both are public values, so this
    /// needs no zeroization. Mirrors `DecapsulationKey::h_cache`.
    pk_cache: std::sync::OnceLock<(Vec<i16>, [u8; 32])>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime decapsulation key (secret key).
///
/// Byte imports validate the two packed ternary fields, the embedded public
/// key's canonical encoding, its cached hash, and the algebraic relationships
/// among `f`, `g⁻¹`, and the public polynomial.
/// Explicit [`Zeroize::zeroize`] preserves the encoded length but permanently
/// invalidates the key material; only dropping or replacing the value is useful
/// afterward.
#[derive(Clone)]
pub struct DecapsulationKey<P: SntrupParams> {
    bytes: Vec<u8>,
    /// Decoded public-key polynomial, cached on first decapsulation.
    ///
    /// Decapsulation re-encrypts against the public key embedded in this secret
    /// key, and decoding it is ~13% of the operation — pure repeated work, since
    /// it is identical on every call. The public key is not secret, so this
    /// needs no zeroization.
    h_cache: std::sync::OnceLock<Vec<i16>>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime ciphertext.
///
/// Imports enforce the parameter set's fixed length but intentionally accept
/// arbitrary contents. Decapsulation must handle malformed ciphertexts through
/// implicit rejection rather than expose a separate validation oracle.
#[derive(Clone)]
pub struct Ciphertext<P: SntrupParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime shared secret.
///
/// Its allocation is erased on drop. Callers remain responsible for copies
/// made through [`AsRef`] or serialization. Explicit [`Zeroize::zeroize`]
/// preserves the fixed 32-byte shape while replacing every byte with zero.
#[derive(Clone)]
pub struct SharedSecret<P: SntrupParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime Key Encapsulation Mechanism parameterized by parameter set.
///
/// Zero-sized marker type providing [`generate_key`](SntrupKem::generate_key).
/// Use the type aliases [`Sntrup653`](crate::Sntrup653),
/// [`Sntrup761`](crate::Sntrup761), [`Sntrup857`](crate::Sntrup857),
/// [`Sntrup953`](crate::Sntrup953), [`Sntrup1013`](crate::Sntrup1013),
/// [`Sntrup1277`](crate::Sntrup1277).
#[derive(Debug, Clone, Copy)]
pub struct SntrupKem<P: SntrupParams>(PhantomData<P>);

// ---------------------------------------------------------------------------
// Internal constructors
// ---------------------------------------------------------------------------

/// Internal `from_vec` constructor for a byte-wrapper type.
macro_rules! impl_from_vec {
    ($ty:ident) => {
        impl<P: SntrupParams> $ty<P> {
            pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
                Self {
                    bytes,
                    _marker: PhantomData,
                }
            }
        }
    };
}

impl_from_vec!(Ciphertext);
impl_from_vec!(SharedSecret);

/// Decodes a public key and computes the per-key values used by
/// encapsulation and decapsulation.
///
/// Both outputs are public. Centralizing their construction keeps typed key
/// import and the lazy operational caches on exactly the same decode path.
fn public_key_metadata<P: SntrupParams>(bytes: &[u8]) -> (Vec<i16>, [u8; 32]) {
    let params = P::params();
    let mut polynomial = vec![0i16; params.p];
    crate::rq::encoding::rq_decode_into(bytes, &mut polynomial, params);

    let mut hash = [0u8; 32];
    crate::utils::hash_prefix(&mut hash, 4, bytes);
    (polynomial, hash)
}

/// Validates an encoded public key by decoding and re-encoding it.
///
/// Variable-radix decoding maps some out-of-range byte strings onto valid
/// coefficients. Requiring a byte-identical round trip rejects those aliases
/// and gives each typed encapsulation key one canonical representation.
fn validate_public_key<P: SntrupParams>(bytes: &[u8]) -> Option<(Vec<i16>, [u8; 32])> {
    let metadata = public_key_metadata::<P>(bytes);
    let canonical = crate::rq::encoding::rq_encode(&metadata.0, P::params());
    if bool::from(canonical.as_slice().ct_eq(bytes)) {
        Some(metadata)
    } else {
        None
    }
}

/// Checks the packed base-4 representation of a ternary polynomial without
/// exiting early on the first invalid trit.
///
/// Full bytes encode four values from `{0, 1, 2}`; the final byte encodes one
/// value and therefore must itself be at most two. A two-bit value of three is
/// the only invalid full-byte digit.
fn is_canonical_small_encoding(bytes: &[u8]) -> bool {
    let Some((&last, body)) = bytes.split_last() else {
        return false;
    };

    let mut invalid = last >> 2;
    invalid |= ((last & 3) ^ 3).wrapping_sub(1) >> 7;
    for &byte in body {
        for shift in [0, 2, 4, 6] {
            let digit = (byte >> shift) & 3;
            invalid |= (digit ^ 3).wrapping_sub(1) >> 7;
        }
    }
    invalid == 0
}

/// Verifies the algebraic relationship among a private key's polynomial fields.
///
/// For a generated key, `h = g/(3f)` in R/q. Multiplying by `3f` must therefore
/// recover coefficients in `{-1, 0, 1}`, and that recovered `g` must multiply
/// by the encoded `g⁻¹` to one in R/3. The fixed weight of `f` is checked at the
/// same boundary. All decoded intermediates remain under erasure guards.
fn private_polynomials_are_coherent(
    f_bytes: &[u8],
    g_inverse_bytes: &[u8],
    public_polynomial: &[i16],
    params: &crate::params::SntrupParameters,
) -> bool {
    let mut f = SecretBuffer::new(vec![0i8; params.p]);
    crate::zx::encoding::decode_into(f_bytes, &mut f, params.p);
    if f.iter().filter(|&&coefficient| coefficient != 0).count() != params.w {
        return false;
    }

    let mut g_inverse = SecretBuffer::new(vec![0i8; params.p]);
    crate::zx::encoding::decode_into(g_inverse_bytes, &mut g_inverse, params.p);

    // Recover `g = 3fh` in R/q. A coherent key's canonical representatives are
    // already small; reducing arbitrary representatives modulo three would
    // accept unrelated public keys, so require the exact small range first.
    let mut f_times_h = SecretBuffer::new(vec![0i16; params.p]);
    crate::rq::mult(&mut f_times_h, public_polynomial, &f, params);
    let mut g = SecretBuffer::new(vec![0i8; params.p]);
    for (g_coefficient, &product) in g.iter_mut().zip(f_times_h.iter()) {
        let recovered = crate::rq::modq::freeze(
            3 * i32::from(product),
            params.q,
            params.barrett1,
            params.barrett2,
        );
        if !(-1..=1).contains(&recovered) {
            return false;
        }
        let Ok(recovered) = i8::try_from(recovered) else {
            return false;
        };
        *g_coefficient = recovered;
    }

    let mut identity = SecretBuffer::new(vec![0i8; params.p]);
    crate::r3::mult(&mut identity, &g, &g_inverse, params.p);
    identity[0] == 1 && identity[1..].iter().all(|&coefficient| coefficient == 0)
}

/// Validates every checkable private-key field and returns the decoded public
/// polynomial for the decapsulation cache.
///
/// Rejection randomness `rho` is intentionally unrestricted. Every other field
/// is canonical, redundant, or algebraically related and is checked here.
fn validate_private_key<P: SntrupParams>(bytes: &[u8]) -> Option<Vec<i16>> {
    let params = P::params();
    let ses = params.small_encode_size;
    let public_start = 2 * ses;
    let public_end = public_start + params.pk_size;
    let cache_start = public_end + ses;

    let f_valid = is_canonical_small_encoding(&bytes[..ses]);
    let g_inverse_valid = is_canonical_small_encoding(&bytes[ses..2 * ses]);
    let (public_polynomial, expected_hash) =
        validate_public_key::<P>(&bytes[public_start..public_end])?;
    let hash_valid = bool::from(expected_hash.ct_eq(&bytes[cache_start..cache_start + 32]));

    let polynomials_valid = f_valid
        && g_inverse_valid
        && private_polynomials_are_coherent(
            &bytes[..ses],
            &bytes[ses..2 * ses],
            &public_polynomial,
            params,
        );

    if polynomials_valid && hash_valid {
        Some(public_polynomial)
    } else {
        None
    }
}

impl<P: SntrupParams> EncapsulationKey<P> {
    /// Constructs a trusted public key produced inside this crate.
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            pk_cache: std::sync::OnceLock::new(),
            _marker: PhantomData,
        }
    }

    /// Constructs an imported, canonical public key with its already-verified
    /// operational metadata installed in the cache.
    fn from_validated_vec(bytes: Vec<u8>, metadata: (Vec<i16>, [u8; 32])) -> Self {
        Self {
            bytes,
            pk_cache: std::sync::OnceLock::from(metadata),
            _marker: PhantomData,
        }
    }

    /// The decoded public-key polynomial and Hash4(pk), computed once and reused.
    #[cfg(feature = "ecap")]
    fn cached_pk(&self) -> &(Vec<i16>, [u8; 32]) {
        self.pk_cache
            .get_or_init(|| public_key_metadata::<P>(&self.bytes))
    }
}

// ---------------------------------------------------------------------------
// DecapsulationKey: extract encapsulation key
// ---------------------------------------------------------------------------

impl<P: SntrupParams> DecapsulationKey<P> {
    /// Constructs a trusted private key produced inside this crate.
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            h_cache: std::sync::OnceLock::new(),
            _marker: PhantomData,
        }
    }

    /// Constructs an imported private key and installs the public polynomial
    /// recovered during validation into the decapsulation cache.
    fn from_validated_vec(bytes: Vec<u8>, public_polynomial: Vec<i16>) -> Self {
        Self {
            bytes,
            h_cache: std::sync::OnceLock::from(public_polynomial),
            _marker: PhantomData,
        }
    }

    /// The decoded public-key polynomial, computed once and reused.
    fn cached_h(&self) -> &[i16] {
        self.h_cache.get_or_init(|| {
            let params = P::params();
            let ses = params.small_encode_size;
            let pk = &self.bytes[2 * ses..2 * ses + params.pk_size];
            let mut h = vec![0i16; params.p];
            crate::rq::encoding::rq_decode_into(pk, &mut h, params);
            h
        })
    }

    /// Get the encapsulation (public) key embedded in this decapsulation key.
    ///
    /// SK layout: f(small_enc) || ginv(small_enc) || pk(pk_size) || rho(small_enc) || hash4(32)
    /// The public key starts at offset `2 * small_encode_size` with length `pk_size`.
    pub fn encapsulation_key(&self) -> EncapsulationKey<P> {
        let params = P::params();
        let pk_start = 2 * params.small_encode_size;
        let pk_end = pk_start + params.pk_size;
        EncapsulationKey::from_vec(self.bytes[pk_start..pk_end].to_vec())
    }
}

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

impl<P: SntrupParams> core::fmt::Debug for EncapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::EncapsulationKey", P::NAME);
        f.debug_struct(&name)
            .field("len", &P::PK_BYTES)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: SntrupParams> core::fmt::Debug for DecapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::DecapsulationKey", P::NAME);
        f.debug_struct(&name).finish()
    }
}

impl<P: SntrupParams> core::fmt::Debug for Ciphertext<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::Ciphertext", P::NAME);
        f.debug_struct(&name)
            .field("len", &P::CT_BYTES)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: SntrupParams> core::fmt::Debug for SharedSecret<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::SharedSecret", P::NAME);
        f.debug_struct(&name).finish()
    }
}

// ---------------------------------------------------------------------------
// AsRef<[u8]>
// ---------------------------------------------------------------------------

/// `AsRef<[u8]>` byte access for a wrapper type.
macro_rules! impl_as_ref {
    ($ty:ident) => {
        impl<P: SntrupParams> AsRef<[u8]> for $ty<P> {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
    };
}

impl_as_ref!(EncapsulationKey);
impl_as_ref!(DecapsulationKey);
impl_as_ref!(Ciphertext);
impl_as_ref!(SharedSecret);

// ---------------------------------------------------------------------------
// TryFrom<&[u8]>
// ---------------------------------------------------------------------------

/// Generates owned and borrowed imports for a fixed-size, non-secret byte
/// wrapper whose wire format intentionally has no canonicality check.
///
/// Ciphertexts use this path because invalid ciphertext content must reach
/// decapsulation's implicit-rejection logic instead of producing an observable
/// parse error.
macro_rules! impl_public_bytes_try_from {
    ($ty:ident, $size:ident) => {
        impl<P: SntrupParams> TryFrom<&[u8]> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                if bytes.len() != P::$size {
                    return Err(Error::InvalidSize {
                        expected: P::$size,
                        actual: bytes.len(),
                    });
                }
                Ok(Self::from_vec(bytes.to_vec()))
            }
        }

        impl<P: SntrupParams> TryFrom<Vec<u8>> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
                if bytes.len() != P::$size {
                    return Err(Error::InvalidSize {
                        expected: P::$size,
                        actual: bytes.len(),
                    });
                }
                Ok(Self::from_vec(bytes))
            }
        }

        impl<P: SntrupParams> TryFrom<&Vec<u8>> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_slice())
            }
        }

        impl<P: SntrupParams> TryFrom<Box<[u8]>> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.into_vec())
            }
        }
    };
}

impl_public_bytes_try_from!(Ciphertext, CT_BYTES);

/// Generates fixed-size imports for a secret byte wrapper.
///
/// Owned malformed inputs are wiped before their allocation is released; a
/// borrowed input remains under the caller's ownership and is copied only
/// after its length is accepted.
macro_rules! impl_secret_bytes_try_from {
    ($ty:ident, $size:ident) => {
        impl<P: SntrupParams> TryFrom<&[u8]> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                if bytes.len() != P::$size {
                    return Err(Error::InvalidSize {
                        expected: P::$size,
                        actual: bytes.len(),
                    });
                }
                Ok(Self::from_vec(bytes.to_vec()))
            }
        }

        impl<P: SntrupParams> TryFrom<Vec<u8>> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
                let mut bytes = SecretBuffer::new(bytes);
                if bytes.len() != P::$size {
                    let actual = bytes.len();
                    return Err(Error::InvalidSize {
                        expected: P::$size,
                        actual,
                    });
                }
                // Transfer the allocation only after validation. The returned
                // secret wrapper takes over the drop-erasure responsibility.
                Ok(Self::from_vec(bytes.take()))
            }
        }

        impl<P: SntrupParams> TryFrom<&Vec<u8>> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_slice())
            }
        }

        impl<P: SntrupParams> TryFrom<Box<[u8]>> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.into_vec())
            }
        }
    };
}

impl_secret_bytes_try_from!(SharedSecret, SS_BYTES);

impl<P: SntrupParams> TryFrom<&[u8]> for EncapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::PK_BYTES {
            return Err(Error::InvalidSize {
                expected: P::PK_BYTES,
                actual: bytes.len(),
            });
        }
        let metadata = validate_public_key::<P>(bytes).ok_or(Error::InvalidEncoding {
            kind: "encapsulation key",
        })?;
        Ok(Self::from_validated_vec(bytes.to_vec(), metadata))
    }
}

impl<P: SntrupParams> TryFrom<Vec<u8>> for EncapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() != P::PK_BYTES {
            return Err(Error::InvalidSize {
                expected: P::PK_BYTES,
                actual: bytes.len(),
            });
        }
        let metadata = validate_public_key::<P>(&bytes).ok_or(Error::InvalidEncoding {
            kind: "encapsulation key",
        })?;
        Ok(Self::from_validated_vec(bytes, metadata))
    }
}

impl<P: SntrupParams> TryFrom<&Vec<u8>> for EncapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: SntrupParams> TryFrom<Box<[u8]>> for EncapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.into_vec())
    }
}

// ---------------------------------------------------------------------------
// PartialEq / Eq (EncapsulationKey, Ciphertext — non-secret, byte equality)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> PartialEq for EncapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: SntrupParams> Eq for EncapsulationKey<P> {}

impl<P: SntrupParams> PartialEq for Ciphertext<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: SntrupParams> Eq for Ciphertext<P> {}

// ---------------------------------------------------------------------------
// ConstantTimeEq / PartialEq / Eq (DecapsulationKey)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> TryFrom<&[u8]> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::SK_BYTES {
            return Err(Error::InvalidSize {
                expected: P::SK_BYTES,
                actual: bytes.len(),
            });
        }
        let public_polynomial = validate_private_key::<P>(bytes).ok_or(Error::InvalidEncoding {
            kind: "decapsulation key",
        })?;
        Ok(Self::from_validated_vec(bytes.to_vec(), public_polynomial))
    }
}

impl<P: SntrupParams> TryFrom<Vec<u8>> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut bytes = SecretBuffer::new(bytes);
        if bytes.len() != P::SK_BYTES {
            let actual = bytes.len();
            return Err(Error::InvalidSize {
                expected: P::SK_BYTES,
                actual,
            });
        }

        let Some(public_polynomial) = validate_private_key::<P>(&bytes) else {
            return Err(Error::InvalidEncoding {
                kind: "decapsulation key",
            });
        };

        // Transfer the allocation directly into the key. This avoids creating
        // a second secret copy; the key assumes its drop-erasure responsibility.
        Ok(Self::from_validated_vec(bytes.take(), public_polynomial))
    }
}

impl<P: SntrupParams> TryFrom<&Vec<u8>> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: SntrupParams> TryFrom<Box<[u8]>> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        // `into_vec` reuses the boxed allocation; the owned `Vec` path then
        // either installs it in the key or wipes it on a size error.
        Self::try_from(bytes.into_vec())
    }
}

impl<P: SntrupParams> ConstantTimeEq for DecapsulationKey<P> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice())
    }
}

impl<P: SntrupParams> PartialEq for DecapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: SntrupParams> Eq for DecapsulationKey<P> {}

// ---------------------------------------------------------------------------
// ConstantTimeEq / PartialEq / Eq (SharedSecret)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> ConstantTimeEq for SharedSecret<P> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice())
    }
}

impl<P: SntrupParams> PartialEq for SharedSecret<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: SntrupParams> Eq for SharedSecret<P> {}

// ---------------------------------------------------------------------------
// Zeroize + Drop (secret types)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> Zeroize for DecapsulationKey<P> {
    fn zeroize(&mut self) {
        // Discard metadata derived from the pre-erasure public key so a later
        // accidental operation cannot combine stale cache state with zeros.
        let _ = self.h_cache.take();
        // `Vec::zeroize` clears the vector length. Wipe the initialized slice
        // instead so the typed wrapper retains its fixed-size memory-safety
        // invariant even though the cryptographic key is now invalid.
        crate::wipe::wipe(self.bytes.as_mut_slice());
    }
}

impl<P: SntrupParams> Drop for DecapsulationKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Marks the private-key wrapper's `Drop` implementation for generic secret
/// containers that require explicit zeroize-on-drop capability.
impl<P: SntrupParams> ZeroizeOnDrop for DecapsulationKey<P> {}

impl<P: SntrupParams> Zeroize for SharedSecret<P> {
    fn zeroize(&mut self) {
        // Preserve the public API's fixed-length invariant while erasing all
        // secret bytes; calling `Vec::zeroize` would clear the length.
        crate::wipe::wipe(self.bytes.as_mut_slice());
    }
}

impl<P: SntrupParams> Drop for SharedSecret<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Marks the shared-secret wrapper's `Drop` implementation for generic secret
/// containers that require explicit zeroize-on-drop capability.
impl<P: SntrupParams> ZeroizeOnDrop for SharedSecret<P> {}

// ---------------------------------------------------------------------------
// KEM operations (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "kgen")]
impl<P: SntrupParams> SntrupKem<P> {
    /// Generate a Streamlined NTRU Prime key pair.
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        let (pk, sk) = crate::ops::keygen(P::params(), rng);
        (
            EncapsulationKey::from_vec(pk),
            DecapsulationKey::from_vec(sk),
        )
    }

    /// Generate a key pair deterministically from a 32-byte seed.
    ///
    /// The seed is expanded via ChaCha20Rng to derive the full key pair.
    /// Identical seeds always produce identical key pairs.
    /// This is a crate-specific convenience API, not the deterministic random
    /// bit generator used by NIST or upstream known-answer test formats.
    ///
    /// Note: `rand_chacha` offers no zeroization support, so the RNG's internal state (which
    /// contains the seed) is dropped without being wiped when this returns. Callers with
    /// strict key-erasure requirements should treat the seed's residency in freed stack
    /// memory as a known limitation of this function.
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
        Self::generate_key(&mut rng)
    }
}

#[cfg(feature = "ecap")]
impl<P: SntrupParams> EncapsulationKey<P> {
    /// Encapsulate: produce a ciphertext and shared secret.
    pub fn encapsulate(&self, rng: &mut impl rand::CryptoRng) -> (Ciphertext<P>, SharedSecret<P>) {
        let (h, pk_hash) = self.cached_pk();
        let (ct, ss) = crate::ops::encaps(h, pk_hash, P::params(), rng);
        (Ciphertext::from_vec(ct), SharedSecret::from_vec(ss))
    }
}

#[cfg(feature = "dcap")]
impl<P: SntrupParams> DecapsulationKey<P> {
    /// Decapsulate: recover shared secret from ciphertext.
    ///
    /// Always returns a shared secret (implicit rejection / IND-CCA2).
    /// On failure, returns a pseudorandom key derived from rho,
    /// indistinguishable from a valid key to an attacker.
    pub fn decapsulate(&self, ct: &Ciphertext<P>) -> SharedSecret<P> {
        let ss = crate::ops::decaps(&self.bytes, self.cached_h(), &ct.bytes, P::params());
        SharedSecret::from_vec(ss)
    }
}

// ---------------------------------------------------------------------------
// Serde (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;

    /// Converts binary serde byte buffers directly into a concrete key wrapper.
    ///
    /// The visitor is parameterized by the destination type, so every owned
    /// buffer follows that type's `TryFrom<Vec<u8>>` policy without type erasure.
    /// Secret wrappers guard the allocation as the first import operation.
    struct BinaryBytesVisitor<T> {
        /// Fixed byte length used to describe the expected binary value.
        expected: usize,
        /// Associates this zero-sized visitor with its concrete output type.
        marker: PhantomData<T>,
    }

    impl<T> BinaryBytesVisitor<T> {
        /// Builds a typed visitor for one fixed-size wire representation.
        fn new(expected: usize) -> Self {
            Self {
                expected,
                marker: PhantomData,
            }
        }
    }

    impl<'de, T> serde::de::Visitor<'de> for BinaryBytesVisitor<T>
    where
        for<'a> T: TryFrom<&'a [u8], Error = Error>,
        T: TryFrom<Vec<u8>, Error = Error>,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(formatter, "exactly {} binary bytes", self.expected)
        }

        fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            T::try_from(bytes).map_err(E::custom)
        }

        fn visit_borrowed_bytes<E: serde::de::Error>(
            self,
            bytes: &'de [u8],
        ) -> Result<Self::Value, E> {
            self.visit_bytes(bytes)
        }

        fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            // Ownership passes immediately to `TryFrom<Vec<u8>>`. For secret
            // targets that function installs an unwind-safe erasure guard
            // before inspecting either the length or the encoding.
            T::try_from(bytes).map_err(E::custom)
        }
    }

    /// Generate `Serialize`/`Deserialize` for a byte-wrapper type.
    ///
    /// Deserialization validates the parameter set's fixed size and keeps the
    /// temporary allocation in `Zeroizing` storage. That policy is harmless for
    /// public values and ensures malformed private keys or shared secrets are
    /// erased on every error path.
    macro_rules! impl_serde {
        ($ty:ident, $size:ident) => {
            impl<P: SntrupParams> serde::Serialize for $ty<P> {
                fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
                }
            }

            impl<'de, P: SntrupParams> serde::Deserialize<'de> for $ty<P> {
                fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    if !d.is_human_readable() {
                        return d.deserialize_byte_buf(BinaryBytesVisitor::<Self>::new(P::$size));
                    }

                    let mut buf = zeroize::Zeroizing::new(vec![0u8; P::$size]);
                    let decoded = serdect::slice::deserialize_hex_or_bin(buf.as_mut_slice(), d)?;
                    if decoded.len() != P::$size {
                        return Err(serde::de::Error::invalid_length(
                            decoded.len(),
                            &concat!(
                                stringify!($ty),
                                " expects exactly P::",
                                stringify!($size),
                                " bytes"
                            ),
                        ));
                    }
                    // Move the validated allocation into the wrapper. `buf`
                    // retains an empty vector, so its zeroizing drop cannot
                    // erase the successfully imported value.
                    Self::try_from(core::mem::take(&mut *buf)).map_err(serde::de::Error::custom)
                }
            }
        };
    }

    impl_serde!(EncapsulationKey, PK_BYTES);
    impl_serde!(DecapsulationKey, SK_BYTES);
    impl_serde!(Ciphertext, CT_BYTES);
    impl_serde!(SharedSecret, SS_BYTES);
}
