#![allow(missing_docs)]

use sntrup::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compile-time assertion used to pin the marker trait promised by secret
/// wrapper types.
fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

/// Both exported secret wrappers advertise their drop-erasure behavior to
/// generic containers and protocol adapters.
#[test]
fn secret_wrappers_implement_zeroize_on_drop() {
    assert_zeroize_on_drop::<DecapsulationKey<Sntrup761Params>>();
    assert_zeroize_on_drop::<SharedSecret<Sntrup761Params>>();
}

// ---------------------------------------------------------------------------
// Implicit rejection: corrupted CT still returns a key, but a different one
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! implicit_rejection_test {
    ($name:ident, $kem:ty, $ct_size:expr) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let (ct, ss_encap) = ek.encapsulate(&mut rng);

            // Corrupt the ciphertext
            let mut ct_bytes = ct.as_ref().to_vec();
            ct_bytes[0] ^= 0xFF;
            ct_bytes[100] ^= 0x42;
            let ct_bad = Ciphertext::try_from(ct_bytes.as_slice()).expect("CT size");

            let ss_decap = dk.decapsulate(&ct_bad);
            assert!(
                ss_encap != ss_decap,
                "corrupted CT must produce different key"
            );

            // Deterministic: same corrupted CT + SK always produces same key
            let ss_decap2 = dk.decapsulate(&ct_bad);
            assert!(
                ss_decap == ss_decap2,
                "repeated decap must be deterministic"
            );
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_653, Sntrup653, 897);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_761, Sntrup761, 1039);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_857, Sntrup857, 1184);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_953, Sntrup953, 1349);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_1013, Sntrup1013, 1455);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_1277, Sntrup1277, 1847);

// ---------------------------------------------------------------------------
// Wrong secret key gives different shared secret
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! wrong_sk_test {
    ($name:ident, $kem:ty) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek1, _dk1) = <$kem>::generate_key(&mut rng);
            let (_ek2, dk2) = <$kem>::generate_key(&mut rng);
            let (ct, ss_encap) = ek1.encapsulate(&mut rng);
            let ss_decap = dk2.decapsulate(&ct);
            assert!(ss_encap != ss_decap, "wrong SK must produce different key");
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_653, Sntrup653);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_761, Sntrup761);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_857, Sntrup857);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_953, Sntrup953);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_1013, Sntrup1013);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_1277, Sntrup1277);

// ---------------------------------------------------------------------------
// Implicit rejection always returns a fixed-size shared secret
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! fixed_rejection_output_test {
    ($name:ident, $kem:ty, $ct_size:expr) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let (ct, _ss) = ek.encapsulate(&mut rng);
            let result = dk.decapsulate(&ct);
            assert_eq!(result.as_ref().len(), 32);

            // Even with garbage ciphertext
            let garbage = vec![0xABu8; $ct_size];
            let garbage_ct = Ciphertext::try_from(garbage.as_slice()).expect("CT size");
            let result2 = dk.decapsulate(&garbage_ct);
            assert_eq!(result2.as_ref().len(), 32);
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
fixed_rejection_output_test!(fixed_rejection_output_653, Sntrup653, 897);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
fixed_rejection_output_test!(fixed_rejection_output_761, Sntrup761, 1039);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
fixed_rejection_output_test!(fixed_rejection_output_857, Sntrup857, 1184);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
fixed_rejection_output_test!(fixed_rejection_output_953, Sntrup953, 1349);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
fixed_rejection_output_test!(fixed_rejection_output_1013, Sntrup1013, 1455);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
fixed_rejection_output_test!(fixed_rejection_output_1277, Sntrup1277, 1847);

// ---------------------------------------------------------------------------
// Canonical key imports and intentionally opaque ciphertext imports
// ---------------------------------------------------------------------------

/// Typed keys reject non-canonical or algebraically inconsistent encodings, while a
/// fixed-size ciphertext remains importable so decapsulation can perform
/// implicit rejection without exposing a parser result.
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
#[test]
fn key_import_validates_coherence_but_ciphertext_import_is_length_only() {
    let mut rng = rand::rng();
    let (ek, dk) = Sntrup761::generate_key(&mut rng);

    let invalid_ek = vec![0xff; Sntrup761Params::PK_BYTES];
    assert!(matches!(
        EncapsulationKey::<Sntrup761Params>::try_from(invalid_ek),
        Err(Error::InvalidEncoding { .. })
    ));

    // Force the first packed ternary digit to the reserved base-4 value 3.
    let mut invalid_polynomial = dk.as_ref().to_vec();
    invalid_polynomial[0] = (invalid_polynomial[0] & !3) | 3;
    assert!(matches!(
        DecapsulationKey::<Sntrup761Params>::try_from(invalid_polynomial),
        Err(Error::InvalidEncoding { .. })
    ));

    // The final 32 private-key bytes redundantly contain Hash4(pk).
    let mut inconsistent_cache = dk.as_ref().to_vec();
    let cache_byte = inconsistent_cache.len() - 1;
    inconsistent_cache[cache_byte] ^= 1;
    assert!(matches!(
        DecapsulationKey::<Sntrup761Params>::try_from(inconsistent_cache),
        Err(Error::InvalidEncoding { .. })
    ));

    // Change only the sign of one nonzero f coefficient. This preserves the
    // canonical ternary encoding and exact weight while breaking h = g/(3f).
    let mut inconsistent_f = dk.as_ref().to_vec();
    let coefficient = (0..Sntrup761Params::params().p)
        .find(|&index| {
            let digit = (inconsistent_f[index / 4] >> (2 * (index % 4))) & 3;
            digit == 1 || digit == 2
        })
        .expect("generated f has fixed nonzero weight");
    let byte = coefficient / 4;
    let shift = 2 * (coefficient % 4);
    inconsistent_f[byte] ^= 3 << shift;
    assert!(matches!(
        DecapsulationKey::<Sntrup761Params>::try_from(inconsistent_f),
        Err(Error::InvalidEncoding { .. })
    ));

    // A public key and its matching cached hash remain structurally valid when
    // transplanted together, but they are not coherent with the first key's f.
    let (_, other_dk) = Sntrup761::generate_key(&mut rng);
    let params = Sntrup761Params::params();
    let public_start = 2 * params.small_encode_size;
    let public_end = public_start + params.pk_size;
    let cache_start = public_end + params.small_encode_size;
    let mut inconsistent_public = dk.as_ref().to_vec();
    inconsistent_public[public_start..public_end]
        .copy_from_slice(&other_dk.as_ref()[public_start..public_end]);
    inconsistent_public[cache_start..].copy_from_slice(&other_dk.as_ref()[cache_start..]);
    assert!(matches!(
        DecapsulationKey::<Sntrup761Params>::try_from(inconsistent_public),
        Err(Error::InvalidEncoding { .. })
    ));

    let arbitrary_ciphertext = vec![0xff; Sntrup761Params::CT_BYTES];
    assert!(Ciphertext::<Sntrup761Params>::try_from(arbitrary_ciphertext).is_ok());

    // Generated encodings remain accepted after the stricter validation.
    assert!(EncapsulationKey::<Sntrup761Params>::try_from(ek.as_ref()).is_ok());
    assert!(DecapsulationKey::<Sntrup761Params>::try_from(dk.as_ref()).is_ok());
}

/// Owned imports transfer their accepted allocations into secret wrappers,
/// avoiding a transient duplicate, and shared secrets expose the documented
/// fixed-size conversion family.
#[test]
fn owned_secret_imports_reuse_valid_allocations() {
    let shared_bytes = vec![0x5a; Sntrup761Params::SS_BYTES];
    let shared_pointer = shared_bytes.as_ptr();
    let shared = SharedSecret::<Sntrup761Params>::try_from(shared_bytes).expect("shared secret");
    assert_eq!(shared.as_ref().as_ptr(), shared_pointer);

    #[cfg(feature = "kgen")]
    {
        let (_, dk) = Sntrup761::generate_key(&mut rand::rng());
        let private_bytes = dk.as_ref().to_vec();
        let private_pointer = private_bytes.as_ptr();
        let imported =
            DecapsulationKey::<Sntrup761Params>::try_from(private_bytes).expect("private key");
        assert_eq!(imported.as_ref().as_ptr(), private_pointer);
    }
}

/// Explicit shared-secret erasure must preserve its fixed-size wrapper shape.
#[test]
fn zeroized_shared_secret_retains_its_length() {
    let mut secret =
        SharedSecret::<Sntrup761Params>::try_from(vec![0x5A; Sntrup761Params::SS_BYTES])
            .expect("shared secret");
    secret.zeroize();

    assert_eq!(secret.as_ref().len(), Sntrup761Params::SS_BYTES);
    assert!(secret.as_ref().iter().all(|&byte| byte == 0));
}

/// Explicit private-key erasure must not violate the length assumptions used
/// by extraction and implicit-rejection decapsulation.
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
#[test]
fn zeroized_decapsulation_key_retains_its_shape() {
    let mut rng = rand::rng();
    let (ek, mut dk) = Sntrup761::generate_key(&mut rng);
    let (ct, _) = ek.encapsulate(&mut rng);
    // Populate the lazy public-polynomial cache before erasure to verify that
    // `zeroize` invalidates it along with the encoded key bytes.
    let _ = dk.decapsulate(&ct);

    dk.zeroize();

    assert_eq!(dk.as_ref().len(), Sntrup761Params::SK_BYTES);
    assert!(dk.as_ref().iter().all(|&byte| byte == 0));
    assert_eq!(
        dk.encapsulation_key().as_ref().len(),
        Sntrup761Params::PK_BYTES
    );
    assert_eq!(
        dk.decapsulate(&ct).as_ref().len(),
        Sntrup761Params::SS_BYTES
    );
}

// ---------------------------------------------------------------------------
// Deterministic keygen from seed
// ---------------------------------------------------------------------------

#[cfg(feature = "kgen")]
macro_rules! deterministic_keygen_test {
    ($name:ident, $kem:ty) => {
        #[test]
        fn $name() {
            let seed = [0xABu8; 32];
            let (ek1, dk1) = <$kem>::generate_key_deterministic(&seed);
            let (ek2, dk2) = <$kem>::generate_key_deterministic(&seed);
            assert_eq!(ek1, ek2, "same seed must produce same EK");
            assert!(dk1 == dk2, "same seed must produce same DK");

            // Different seed produces different key
            let (ek3, _dk3) = <$kem>::generate_key_deterministic(&[0xCDu8; 32]);
            assert_ne!(ek1, ek3, "different seed must produce different EK");
        }
    };
}

#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_653, Sntrup653);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_761, Sntrup761);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_857, Sntrup857);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_953, Sntrup953);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_1013, Sntrup1013);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_1277, Sntrup1277);

/// A caller seed must select independent deterministic streams for different
/// parameter-set domains.
#[cfg(feature = "kgen")]
#[test]
fn deterministic_keygen_is_parameter_separated() {
    let seed = [0x73; 32];
    let public_keys = [
        Sntrup653::generate_key_deterministic(&seed)
            .0
            .as_ref()
            .to_vec(),
        Sntrup761::generate_key_deterministic(&seed)
            .0
            .as_ref()
            .to_vec(),
        Sntrup857::generate_key_deterministic(&seed)
            .0
            .as_ref()
            .to_vec(),
        Sntrup953::generate_key_deterministic(&seed)
            .0
            .as_ref()
            .to_vec(),
        Sntrup1013::generate_key_deterministic(&seed)
            .0
            .as_ref()
            .to_vec(),
        Sntrup1277::generate_key_deterministic(&seed)
            .0
            .as_ref()
            .to_vec(),
    ];

    for (index, left) in public_keys.iter().enumerate() {
        for right in &public_keys[index + 1..] {
            assert_ne!(left, right, "parameter domains reused a keygen stream");
        }
    }
}

// ---------------------------------------------------------------------------
// Extract encapsulation key from decapsulation key
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! ek_from_dk_test {
    ($name:ident, $kem:ty) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let ek_extracted = dk.encapsulation_key();
            assert_eq!(ek, ek_extracted, "extracted EK must match original");

            // Encapsulating with the extracted key should produce a valid shared secret
            let (ct, ss_encap) = ek_extracted.encapsulate(&mut rng);
            let ss_decap = dk.decapsulate(&ct);
            assert!(ss_encap == ss_decap, "shared secrets must match");
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_653, Sntrup653);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_761, Sntrup761);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_857, Sntrup857);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_953, Sntrup953);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_1013, Sntrup1013);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_1277, Sntrup1277);

// ---------------------------------------------------------------------------
// TryFrom with wrong sizes
// ---------------------------------------------------------------------------

macro_rules! try_from_invalid_size_test {
    ($name:ident, $ek:ty, $dk:ty, $ct:ty) => {
        #[test]
        fn $name() {
            let short = vec![0u8; 16];
            assert!(<$ek>::try_from(short.as_slice()).is_err());
            assert!(<$dk>::try_from(short.as_slice()).is_err());
            assert!(<$ct>::try_from(short.as_slice()).is_err());
        }
    };
}

try_from_invalid_size_test!(
    try_from_invalid_653,
    sntrup653::EncapsulationKey,
    sntrup653::DecapsulationKey,
    sntrup653::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_761,
    sntrup761::EncapsulationKey,
    sntrup761::DecapsulationKey,
    sntrup761::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_857,
    sntrup857::EncapsulationKey,
    sntrup857::DecapsulationKey,
    sntrup857::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_953,
    sntrup953::EncapsulationKey,
    sntrup953::DecapsulationKey,
    sntrup953::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_1013,
    sntrup1013::EncapsulationKey,
    sntrup1013::DecapsulationKey,
    sntrup1013::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_1277,
    sntrup1277::EncapsulationKey,
    sntrup1277::DecapsulationKey,
    sntrup1277::Ciphertext
);

// ---------------------------------------------------------------------------
// TryFrom / AsRef roundtrip
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! bytes_roundtrip_test {
    ($name:ident, $kem:ty) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let (ct, ss) = ek.encapsulate(&mut rng);

            // EK roundtrip
            let ek2 = EncapsulationKey::try_from(ek.as_ref()).expect("EK roundtrip");
            assert_eq!(ek, ek2);

            // DK roundtrip
            let dk2 = DecapsulationKey::try_from(dk.as_ref()).expect("DK roundtrip");
            assert!(dk == dk2, "DK must match");

            // CT roundtrip
            let ct2 = Ciphertext::try_from(ct.as_ref()).expect("CT roundtrip");
            assert_eq!(ct, ct2);

            // Full KEM roundtrip through bytes
            let ss_decap = dk2.decapsulate(&ct2);
            assert!(ss == ss_decap, "KEM roundtrip through bytes must work");
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_653, Sntrup653);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_761, Sntrup761);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_857, Sntrup857);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_953, Sntrup953);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_1013, Sntrup1013);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_1277, Sntrup1277);
