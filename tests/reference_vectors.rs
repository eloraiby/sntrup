#![allow(missing_docs)]
#![cfg(all(feature = "kgen", feature = "ecap"))]

//! Compact known-answer tests covering all six parameter sets.
//!
//! The expected digests were generated with libntruprime 20260717. Both
//! implementations received byte-identical ChaCha20 streams: `[id; 32]` for
//! key generation and `[id ^ 0x80; 32]` for encapsulation. Before recording the
//! fixtures, the complete public key, private key, ciphertext, and shared key
//! matched byte for byte. Hashing their unambiguous fixed-length concatenation
//! keeps the checked-in fixtures small while pinning the full outputs.

use rand::SeedableRng;
use sha2::{Digest, Sha512};
use sntrup::{
    Sntrup653Params, Sntrup761Params, Sntrup857Params, Sntrup953Params, Sntrup1013Params,
    Sntrup1277Params, SntrupKem, SntrupParams,
};

/// Recreates one independently generated reference transcript and compares
/// its SHA-512 digest with the checked-in fixture.
fn reference_transcript<P: SntrupParams>(id: u8, expected: &str) {
    let (encapsulation_key, decapsulation_key) =
        SntrupKem::<P>::generate_key_deterministic(&[id; 32]);

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([id ^ 0x80; 32]);
    let (ciphertext, shared_secret) = encapsulation_key.encapsulate(&mut rng);

    let mut digest = Sha512::new();
    digest.update(encapsulation_key.as_ref());
    digest.update(decapsulation_key.as_ref());
    digest.update(ciphertext.as_ref());
    digest.update(shared_secret.as_ref());
    assert_eq!(hex::encode(digest.finalize()), expected, "{}", P::NAME);
}

/// Defines one test without hiding the generic transcript construction or the
/// provenance of its independently generated expected digest.
macro_rules! reference_vector {
    ($name:ident, $params:ty, $id:expr, $digest:literal) => {
        #[test]
        fn $name() {
            reference_transcript::<$params>($id, $digest);
        }
    };
}

reference_vector!(
    libntruprime_653,
    Sntrup653Params,
    0x11,
    "d984ecbd273164645f05435aa46b8afec170a6a783a5d29fd2f1659d0fe57a9f88a9aff9ff1952ae6bf7c339b9447b5de2023d574dd57424977e2100f26bb300"
);
reference_vector!(
    libntruprime_761,
    Sntrup761Params,
    0x22,
    "aee544bf265fe3c3b5d917b0a15886a2094ca4d7ceca22b29df1d0c68b523ab3f5217edff1bae2e678a51f8b0ab1414b9015c43866037d74d410d0f3cc48cff0"
);
reference_vector!(
    libntruprime_857,
    Sntrup857Params,
    0x33,
    "3f84bc948e5003cd79635977b34dc323257f9e6c760ff3c51f572787c353968efcaf50e56702735a815f1ea7eb00a5b34ee99e4a5ec37bd1a8f6c172a02ccee2"
);
reference_vector!(
    libntruprime_953,
    Sntrup953Params,
    0x44,
    "6701740623738eab0837f1645b2aa85a356f66c8a7b04a169dc2c29bfedec748f8bca9b68298bc32d616d3de9c793fdeb237c01ba29c4928a0ff15a126f2abbc"
);
reference_vector!(
    libntruprime_1013,
    Sntrup1013Params,
    0x55,
    "a85ad462642ba697b7fe957892259782aefe8a445aca7b750ed1ac16887390b981ee40ae48f622df8856514d240d9ccba23b48aacdd7fe7ae935530667b6cfab"
);
reference_vector!(
    libntruprime_1277,
    Sntrup1277Params,
    0x66,
    "f6ebcd20a4552561853b6c1d7f4606995d9eda1d64733cd041d884bb16a996122dd4fc11e02d86979522a057739db7d694ba21e1f271d62260f6f44d25658664"
);
