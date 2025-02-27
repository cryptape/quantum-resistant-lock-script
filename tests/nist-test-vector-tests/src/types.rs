/// This file contains the serde structure for NIST's internalProject.json file
use ckb_fips205_utils::ParamId;
use serde::{Deserialize, Serialize};
use serde_string_enum::{DeserializeLabeledStringEnum, SerializeLabeledStringEnum};

#[derive(
    Copy,
    Clone,
    Debug,
    SerializeLabeledStringEnum,
    DeserializeLabeledStringEnum,
    PartialEq,
    Eq,
    Hash,
)]
pub enum HashAlgorithm {
    #[string = "none"]
    None,
    #[string = "SHA2-224"]
    Sha2224,
    #[string = "SHA2-256"]
    Sha2256,
    #[string = "SHA2-384"]
    Sha2384,
    #[string = "SHA2-512"]
    Sha2512,
    #[string = "SHA2-512/224"]
    Sha2512224,
    #[string = "SHA2-512/256"]
    Sha2512256,
    #[string = "SHA3-224"]
    Sha3224,
    #[string = "SHA3-256"]
    Sha3256,
    #[string = "SHA3-384"]
    Sha3384,
    #[string = "SHA3-512"]
    Sha3512,
    #[string = "SHAKE-128"]
    Shake128,
    #[string = "SHAKE-256"]
    Shake256,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct TestCase {
    pub tc_id: usize,
    pub test_passed: bool,
    pub deferred: bool,
    pub sk: HexString,
    pub pk: HexString,
    pub additional_randomness: HexString,
    pub message: HexString,
    pub context: Option<HexString>,
    pub hash_alg: HashAlgorithm,
    pub signature: HexString,
    pub reason: String,
}

#[derive(
    Copy,
    Clone,
    Debug,
    SerializeLabeledStringEnum,
    DeserializeLabeledStringEnum,
    PartialEq,
    Eq,
    Hash,
)]
pub enum SignatureInterface {
    #[string = "internal"]
    Internal,
    #[string = "external"]
    External,
}

#[derive(
    Copy,
    Clone,
    Debug,
    SerializeLabeledStringEnum,
    DeserializeLabeledStringEnum,
    PartialEq,
    Eq,
    Hash,
)]
pub enum PreHash {
    #[string = "pure"]
    Pure,
    #[string = "preHash"]
    PreHash,
    #[string = "none"]
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct TestGroup {
    pub tg_id: usize,
    pub test_type: String,
    pub parameter_set: ParamId,
    pub signature_interface: SignatureInterface,
    pub pre_hash: PreHash,
    pub tests: Vec<TestCase>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct TestSuite {
    pub vs_id: usize,
    pub algorithm: String,
    pub mode: String,
    pub revision: String,
    pub is_sample: bool,
    pub test_groups: Vec<TestGroup>,
}

// Adapted from https://github.com/nervosnetwork/ckb/blob/8444466ed8bf16545d7346855244711faa7858e8/util/jsonrpc-types/src/bytes.rs#L18
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HexString(pub Vec<u8>);

impl Serialize for HexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode_upper(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(HexVisitor)
    }
}

struct HexVisitor;

impl serde::de::Visitor<'_> for HexVisitor {
    type Value = HexString;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a hex string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() & 1 != 0 {
            return Err(E::invalid_length(v.len(), &"even length"));
        }

        let bytes = &v.as_bytes();
        let mut buffer = vec![0; bytes.len() >> 1]; // we checked length
        hex::decode_to_slice(bytes, &mut buffer).map_err(|e| E::custom(format_args!("{e:?}")))?;
        Ok(HexString(buffer))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v)
    }
}
