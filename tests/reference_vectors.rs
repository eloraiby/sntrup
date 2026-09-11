#![allow(missing_docs)]
#![cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]

//! Compact known-answer tests covering all six parameter sets.
//!
//! The expected digests were generated with libntruprime 20260717. Both
//! implementations received byte-identical ChaCha20 streams: `[id; 32]` for
//! key generation and `[id ^ 0x80; 32]` for encapsulation. Before recording the
//! fixtures, the complete public key, private key, ciphertext, and shared key
//! matched byte for byte. The independent implementation also decapsulated the
//! valid ciphertext and five fixed invalid variants. Hashing the generation
//! transcript keeps its fixture compact; rejection keys remain explicit so
//! implicit-rejection behavior is pinned independently rather than circularly.

use rand::SeedableRng;
use sha2::{Digest, Sha512};
use sntrup::{
    Ciphertext, DecapsulationKey, Sntrup653Params, Sntrup761Params, Sntrup857Params,
    Sntrup953Params, Sntrup1013Params, Sntrup1277Params, SntrupKem, SntrupParams,
};

/// Independent outputs for one deterministic KEM and rejection transcript.
struct ReferenceOutputs {
    /// SHA-512 of `pk || sk || ct || encapsulated_shared_secret`.
    transcript_digest: &'static str,
    /// Shared secret obtained by independently decapsulating the valid ciphertext.
    valid: &'static str,
    /// Rejection key after flipping the final confirmation-hash bit.
    confirmation_bit: &'static str,
    /// Rejection key after flipping the first rounded-polynomial bit.
    rounded_bit: &'static str,
    /// Rejection key for an all-zero fixed-size ciphertext.
    all_zero: &'static str,
    /// Rejection key for an all-`0xff` fixed-size ciphertext.
    all_ff: &'static str,
    /// Rejection key after flipping the final rounded-polynomial byte's high bit.
    rounded_boundary: &'static str,
}

/// Recreates one independently generated reference transcript and compares
/// generation, valid decapsulation, and invalid decapsulation with fixtures.
fn reference_transcript<P: SntrupParams>(id: u8, expected: &ReferenceOutputs) {
    // Conformance is defined by the random bytes supplied to key generation,
    // not by this crate's parameter-separated deterministic convenience API.
    let mut key_rng = rand_chacha::ChaCha20Rng::from_seed([id; 32]);
    let (encapsulation_key, decapsulation_key) = SntrupKem::<P>::generate_key(&mut key_rng);

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([id ^ 0x80; 32]);
    let (ciphertext, shared_secret) = encapsulation_key.encapsulate(&mut rng);

    let mut digest = Sha512::new();
    digest.update(encapsulation_key.as_ref());
    digest.update(decapsulation_key.as_ref());
    digest.update(ciphertext.as_ref());
    digest.update(shared_secret.as_ref());
    assert_eq!(
        hex::encode(digest.finalize()),
        expected.transcript_digest,
        "{} generation transcript",
        P::NAME
    );

    /// Imports and decapsulates one fixed-size ciphertext variant before
    /// comparing the complete 32-byte result with its independent fixture.
    fn assert_decap<P: SntrupParams>(
        key: &DecapsulationKey<P>,
        bytes: Vec<u8>,
        label: &str,
        expected: &str,
    ) {
        let ciphertext = Ciphertext::<P>::try_from(bytes).expect("fixed reference length");
        assert_eq!(
            hex::encode(key.decapsulate(&ciphertext).as_ref()),
            expected,
            "{} {label}",
            P::NAME
        );
    }

    assert_eq!(
        hex::encode(decapsulation_key.decapsulate(&ciphertext).as_ref()),
        expected.valid,
        "{} valid decapsulation",
        P::NAME
    );
    assert_eq!(
        hex::encode(shared_secret.as_ref()),
        expected.valid,
        "{} encapsulation fixture",
        P::NAME
    );

    let mut changed = ciphertext.as_ref().to_vec();
    changed[P::CT_BYTES - 1] ^= 1;
    assert_decap(
        &decapsulation_key,
        changed,
        "confirmation bit",
        expected.confirmation_bit,
    );

    let mut changed = ciphertext.as_ref().to_vec();
    changed[0] ^= 1;
    assert_decap(
        &decapsulation_key,
        changed,
        "rounded bit",
        expected.rounded_bit,
    );

    assert_decap(
        &decapsulation_key,
        vec![0; P::CT_BYTES],
        "all-zero ciphertext",
        expected.all_zero,
    );
    assert_decap(
        &decapsulation_key,
        vec![0xff; P::CT_BYTES],
        "all-ff ciphertext",
        expected.all_ff,
    );

    let mut changed = ciphertext.as_ref().to_vec();
    changed[P::CT_BYTES - 33] ^= 0x80;
    assert_decap(
        &decapsulation_key,
        changed,
        "rounded boundary",
        expected.rounded_boundary,
    );
}

/// Defines one test without hiding the generic transcript construction or the
/// provenance of its independently generated expected digest.
macro_rules! reference_vector {
    ($name:ident, $params:ty, $id:expr, $digest:literal, $valid:literal, $confirm:literal, $rounded:literal, $zero:literal, $ff:literal, $boundary:literal) => {
        #[test]
        fn $name() {
            reference_transcript::<$params>(
                $id,
                &ReferenceOutputs {
                    transcript_digest: $digest,
                    valid: $valid,
                    confirmation_bit: $confirm,
                    rounded_bit: $rounded,
                    all_zero: $zero,
                    all_ff: $ff,
                    rounded_boundary: $boundary,
                },
            );
        }
    };
}

reference_vector!(
    libntruprime_653,
    Sntrup653Params,
    0x11,
    "d984ecbd273164645f05435aa46b8afec170a6a783a5d29fd2f1659d0fe57a9f88a9aff9ff1952ae6bf7c339b9447b5de2023d574dd57424977e2100f26bb300",
    "59e501879702bf9fca79d9c8271ce0975a253d3dca18380dce00aaa62ed9959f",
    "a9b22fe318278d67de523aff7df029b0ccd6e39c6c4af97b8ee049bd61703894",
    "8f2dd3894089f541447a3313679ec378e52f938b6b275bacb8b2c03bce398b59",
    "0ce1b8507576a36238547bf1dbc5b67127ed1e87e7d24ed4865ff3bdb00c42c4",
    "b91bc4ba98e04fb6bd0f26e85587b0ebfdee4371ade777dd9fc87265b5167378",
    "a290154ba7e3e8a6b2bf02ff6da6d2dac6949e5d5ace64633e76d7c2a4862aaa"
);
reference_vector!(
    libntruprime_761,
    Sntrup761Params,
    0x22,
    "aee544bf265fe3c3b5d917b0a15886a2094ca4d7ceca22b29df1d0c68b523ab3f5217edff1bae2e678a51f8b0ab1414b9015c43866037d74d410d0f3cc48cff0",
    "cd2045e12ff3cb8e277d8250ce720e293dc43f90f1435d242b09f96206bfefdf",
    "f03d66ff75cedf82d5995d6213fc2f01319b99c196df511c934b5d3895e3e67f",
    "29dde5fad812d21c84f0f90944541118039162cded20c72f1498fae96cb85b98",
    "21f3272cef8967619f4b4e9239d4937cb4e3dc7d96db5ff4bd745d6bb4b81606",
    "7d75962a76e96905fb639840e70993ef126f0358290fc90d634c515dfef382bb",
    "c77053ae0ff0444ecc5ac19291a728efb183d67a999994a298e100623db51635"
);
reference_vector!(
    libntruprime_857,
    Sntrup857Params,
    0x33,
    "3f84bc948e5003cd79635977b34dc323257f9e6c760ff3c51f572787c353968efcaf50e56702735a815f1ea7eb00a5b34ee99e4a5ec37bd1a8f6c172a02ccee2",
    "2f477ee85cb9f82481b1b0d8cf17cabcd7a2c23ec0dca6d8aa83fc7ed5a82dbe",
    "61b9b1c31c0a85487ab9dde3e6ff323d707281fe215a0873b084636830b858c9",
    "b84b6941f9446b490589f8cb251ebad2a471483c685f8f1bb812108dbbb12318",
    "165a81b3acceb0be58aeb9a51cb5868b376d2ba96c428261791da0372ab7230f",
    "b747716a918358fb04fd1db588b6c86c2faa2dfd2becadfbea2f9dbaa4b55fe7",
    "a0ffb3b1baea56f15eb693fbe11f8003d1fbb6cdcaaed609333d3f7a71033697"
);
reference_vector!(
    libntruprime_953,
    Sntrup953Params,
    0x44,
    "6701740623738eab0837f1645b2aa85a356f66c8a7b04a169dc2c29bfedec748f8bca9b68298bc32d616d3de9c793fdeb237c01ba29c4928a0ff15a126f2abbc",
    "2e2bc3f72766e87ccdb8f34af155c1f1a8929e9f605538e9b48b7422d555548b",
    "646e286942a2ec5d183c8e0b05a4408f37c2a822b255457128c7f08a4d197026",
    "61e6fbbd684c943c162ed8582e73b9e0a6df2da16182d7da09ecaf6d9517ca36",
    "bb933709c88311f71f5244d5af571dac95a1e678d927e5242e6887eaad501fe3",
    "ff476059ae077f5d54fb1e3bf89f24743ea9b9a7864458cd86b659f222ab7ee7",
    "77bf95633c8cb953eb844c20be99f48554180bec92c5c9c7cba66a4a894729a8"
);
reference_vector!(
    libntruprime_1013,
    Sntrup1013Params,
    0x55,
    "a85ad462642ba697b7fe957892259782aefe8a445aca7b750ed1ac16887390b981ee40ae48f622df8856514d240d9ccba23b48aacdd7fe7ae935530667b6cfab",
    "78cf9d3aae9d7c5a2ad5e22818adfafc1a37a769b4af1d2d92c5c49c5648e3d0",
    "1e6892cf9960f22888654a41cd69bce7825fc203afa998d835214cb75d5ab1e4",
    "99a2ee8c9ab6c71b2558e915404a30db595a0271b66c77809c373937a0a91597",
    "8bbcb433afdb4e75e92c0fd122b2ee7b63a345250c3b4e872a4665dda826c9f4",
    "9363d379de38a21cc31aede37396a1289f4fa483448eefee8148af6a880dd174",
    "974cc8a1e484a1c508e34e225a519d5a9bd08c4c579dc511cc1047bc57a2f450"
);
reference_vector!(
    libntruprime_1277,
    Sntrup1277Params,
    0x66,
    "f6ebcd20a4552561853b6c1d7f4606995d9eda1d64733cd041d884bb16a996122dd4fc11e02d86979522a057739db7d694ba21e1f271d62260f6f44d25658664",
    "70bbf71dda19feade3ac85f7d4e78e212c6eff20d66e7a64702e0b228b948b81",
    "511d568a69b9cf791b296e9e8234829bcbcedb4cdd4703f1ec1415b19d4473b3",
    "1d4843cdbe94edf037d4ce241de83bdd64b933e6fcfa5ce6efaf337d319c0207",
    "dd05ae51afa65def3fb3c4ca44454671a60c5ada025b07f8e2b11dd50642ba9e",
    "f70c50f0a9ef999606a42f2d2190d24c5e47f5693029a671846aba889747eb0e",
    "987f0994656926131dd138c5443d0d35580ed553eda85e8e67841114db253925"
);
