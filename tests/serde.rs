#![allow(missing_docs)]
#![cfg(feature = "serde")]

use sntrup::*;

/// Minimal non-human-readable deserializer that transfers an owned byte
/// buffer through `Visitor::visit_byte_buf`.
///
/// This pins the path used by binary formats without adding a particular wire
/// format as a development dependency.
struct OwnedBytesDeserializer {
    /// Buffer whose ownership must transfer to the crate's typed serde visitor.
    bytes: Vec<u8>,
}

impl<'de> serde::Deserializer<'de> for OwnedBytesDeserializer {
    type Error = serde::de::value::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_byte_buf(self.bytes)
    }

    fn deserialize_byte_buf<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_byte_buf(self.bytes)
    }

    fn is_human_readable(&self) -> bool {
        false
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes option unit unit_struct newtype_struct seq tuple tuple_struct map
        struct enum identifier ignored_any
    }
}

/// Deserializes one owned binary byte buffer into a concrete wrapper type.
fn from_owned_binary<'de, T: serde::Deserialize<'de>>(
    bytes: Vec<u8>,
) -> Result<T, serde::de::value::Error> {
    T::deserialize(OwnedBytesDeserializer { bytes })
}

macro_rules! serde_json_test {
    ($name:ident, $kem:ty, $params:ty, $pk_size:expr, $ct_size:expr) => {
        mod $name {
            use super::*;

            #[test]
            fn json_roundtrip_encapsulation_key() {
                let mut rng = rand::rng();
                let (ek, _dk) = <$kem>::generate_key(&mut rng);
                let json = serde_json::to_string(&ek).expect("serialize EK");
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
                assert!(parsed.is_string(), "EK should serialize as hex string");
                assert_eq!(
                    parsed.as_str().expect("str").len(),
                    $pk_size * 2,
                    "hex length mismatch"
                );
                let ek2: EncapsulationKey<$params> =
                    serde_json::from_str(&json).expect("deserialize EK");
                assert_eq!(ek, ek2);
            }

            #[test]
            fn json_roundtrip_decapsulation_key() {
                let mut rng = rand::rng();
                let (_ek, dk) = <$kem>::generate_key(&mut rng);
                let json = serde_json::to_string(&dk).expect("serialize DK");
                let dk2: DecapsulationKey<$params> =
                    serde_json::from_str(&json).expect("deserialize DK");
                assert!(dk == dk2, "DK must match after JSON roundtrip");
            }

            #[test]
            fn json_roundtrip_ciphertext() {
                let mut rng = rand::rng();
                let (ek, _dk) = <$kem>::generate_key(&mut rng);
                let (ct, _ss) = ek.encapsulate(&mut rng);
                let json = serde_json::to_string(&ct).expect("serialize CT");
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
                assert!(parsed.is_string(), "CT should serialize as hex string");
                assert_eq!(
                    parsed.as_str().expect("str").len(),
                    $ct_size * 2,
                    "hex length mismatch"
                );
                let ct2: Ciphertext<$params> = serde_json::from_str(&json).expect("deserialize CT");
                assert_eq!(ct, ct2);
            }

            #[test]
            fn json_roundtrip_shared_secret() {
                let mut rng = rand::rng();
                let (ek, _dk) = <$kem>::generate_key(&mut rng);
                let (_ct, ss) = ek.encapsulate(&mut rng);
                let json = serde_json::to_string(&ss).expect("serialize SS");
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
                assert!(parsed.is_string(), "SS should serialize as hex string");
                assert_eq!(
                    parsed.as_str().expect("str").len(),
                    64,
                    "hex length mismatch"
                );
                let ss2: SharedSecret<$params> =
                    serde_json::from_str(&json).expect("deserialize SS");
                assert!(ss == ss2, "SS must match after JSON roundtrip");
            }

            #[test]
            fn json_full_kem_roundtrip() {
                let mut rng = rand::rng();
                let (ek, dk) = <$kem>::generate_key(&mut rng);
                let (ct, ss_encap) = ek.encapsulate(&mut rng);

                let dk_json = serde_json::to_string(&dk).expect("serialize DK");
                let ct_json = serde_json::to_string(&ct).expect("serialize CT");

                let dk2: DecapsulationKey<$params> =
                    serde_json::from_str(&dk_json).expect("deserialize DK");
                let ct2: Ciphertext<$params> =
                    serde_json::from_str(&ct_json).expect("deserialize CT");

                let ss_decap = dk2.decapsulate(&ct2);
                assert!(ss_encap == ss_decap, "KEM roundtrip through JSON must work");
            }
        }
    };
}

mod reject_malformed_input {
    use super::*;

    /// Inputs shorter than the expected size must be rejected, not zero-padded.
    #[test]
    fn short_input_rejected() {
        let json = "\"deadbeef\""; // 4 bytes — far shorter than any expected size
        assert!(
            serde_json::from_str::<EncapsulationKey<Sntrup761Params>>(json).is_err(),
            "short EncapsulationKey input must be rejected, not zero-padded"
        );
        assert!(
            serde_json::from_str::<DecapsulationKey<Sntrup761Params>>(json).is_err(),
            "short DecapsulationKey input must be rejected, not zero-padded"
        );
        assert!(
            serde_json::from_str::<Ciphertext<Sntrup761Params>>(json).is_err(),
            "short Ciphertext input must be rejected, not zero-padded"
        );
        assert!(
            serde_json::from_str::<SharedSecret<Sntrup761Params>>(json).is_err(),
            "short SharedSecret input must be rejected, not zero-padded"
        );
    }

    /// Empty input must be rejected for all four types.
    #[test]
    fn empty_input_rejected() {
        let json = "\"\"";
        assert!(serde_json::from_str::<EncapsulationKey<Sntrup761Params>>(json).is_err());
        assert!(serde_json::from_str::<DecapsulationKey<Sntrup761Params>>(json).is_err());
        assert!(serde_json::from_str::<Ciphertext<Sntrup761Params>>(json).is_err());
        assert!(serde_json::from_str::<SharedSecret<Sntrup761Params>>(json).is_err());
    }
}

mod binary_input {
    use super::*;

    /// Exact-size owned binary data must transfer into the secret wrapper.
    #[test]
    fn exact_shared_secret_is_accepted() {
        let bytes = vec![0xA5; Sntrup761Params::SS_BYTES];
        let secret: SharedSecret<Sntrup761Params> =
            from_owned_binary(bytes.clone()).expect("exact shared secret");
        assert_eq!(secret.as_ref(), bytes);
    }

    /// Both sides of the length boundary must fail through the owned-buffer path.
    #[test]
    fn short_and_oversized_secret_values_are_rejected() {
        for length in [
            Sntrup761Params::SS_BYTES - 1,
            Sntrup761Params::SS_BYTES + 1,
            Sntrup761Params::SS_BYTES + 4096,
        ] {
            assert!(
                from_owned_binary::<SharedSecret<Sntrup761Params>>(vec![0x5A; length]).is_err(),
                "owned secret length {length} must be rejected"
            );
        }
    }

    /// An exact-size but structurally invalid private key must be rejected only
    /// after the owned allocation is under the secret import guard.
    #[test]
    fn malformed_decapsulation_key_is_rejected() {
        assert!(
            from_owned_binary::<DecapsulationKey<Sntrup761Params>>(vec![
                0xFF;
                Sntrup761Params::SK_BYTES
            ])
            .is_err()
        );
    }
}

serde_json_test!(serde_653, Sntrup653, Sntrup653Params, 994, 897);
serde_json_test!(serde_761, Sntrup761, Sntrup761Params, 1158, 1039);
serde_json_test!(serde_857, Sntrup857, Sntrup857Params, 1322, 1184);
serde_json_test!(serde_953, Sntrup953, Sntrup953Params, 1505, 1349);
serde_json_test!(serde_1013, Sntrup1013, Sntrup1013Params, 1623, 1455);
serde_json_test!(serde_1277, Sntrup1277, Sntrup1277Params, 2067, 1847);
