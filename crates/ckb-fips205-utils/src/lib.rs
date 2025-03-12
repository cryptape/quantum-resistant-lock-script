#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(feature = "signing")]
pub mod ckb_tx_message_all_from_mock_tx;
#[cfg(feature = "signing")]
pub mod signing;

pub mod ckb_tx_message_all_in_ckb_vm;
#[cfg(feature = "verifying")]
pub mod verifying;

#[cfg(feature = "message")]
pub mod message;

use ckb_hash::{Blake2b, Blake2bBuilder};
use ckb_rust_std::io;
use ckb_std::{assert, assert_eq, asserts::expect_result};
use int_enum::IntEnum;
#[cfg(feature = "serde")]
use serde_string_enum::{DeserializeLabeledStringEnum, SerializeLabeledStringEnum};

/// Sole truth for param ID definitions in current repository
/// It's trivial to write From / TryFrom trait impls ourselves. However,
/// we leverage IntEnum so we only maintain the mapping between
/// enum variants and the actual int values once, avoiding any potential
/// mistakes as much as possible.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, IntEnum)]
#[cfg_attr(
    feature = "serde",
    derive(SerializeLabeledStringEnum, DeserializeLabeledStringEnum)
)]
pub enum ParamId {
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-128f")]
    Sha2128F = 48,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-128s")]
    Sha2128S = 49,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-192f")]
    Sha2192F = 50,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-192s")]
    Sha2192S = 51,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-256f")]
    Sha2256F = 52,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-256s")]
    Sha2256S = 53,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-128f")]
    Shake128F = 54,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-128s")]
    Shake128S = 55,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-192f")]
    Shake192F = 56,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-192s")]
    Shake192S = 57,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-256f")]
    Shake256F = 58,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-256s")]
    Shake256S = 59,
}

pub fn iterate_param_id<F>(mut f: F)
where
    F: FnMut(ParamId),
{
    for i in 0..=u8::MAX {
        if let Ok(param_id) = i.try_into() {
            f(param_id);
        }
    }
}

#[cfg(feature = "std")]
pub fn collect_param_ids() -> Vec<ParamId> {
    let mut res = vec![];

    iterate_param_id(|param_id| res.push(param_id));

    res
}

pub fn single_sign_script_args_prefix(param_id: ParamId) -> [u8; 5] {
    [0x80, 0x01, 0x01, 0x01, construct_flag(param_id, false)]
}

pub fn single_sign_witness_prefix(param_id: ParamId) -> [u8; 5] {
    let mut prefix = single_sign_script_args_prefix(param_id);
    prefix[4] |= construct_flag(param_id, true);
    prefix
}

pub struct Hasher(Blake2b);

impl Hasher {
    pub fn hash(self) -> [u8; 32] {
        let mut result = [0u8; 32];
        self.0.finalize(&mut result);
        result
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn script_args_hasher() -> Self {
        Hasher(
            Blake2bBuilder::new(32)
                .personal(b"ckb-sphincs+-sct")
                .build(),
        )
    }

    pub fn message_hasher() -> Self {
        Hasher(
            Blake2bBuilder::new(32)
                .personal(b"ckb-sphincs+-msg")
                .build(),
        )
    }
}

impl io::Write for Hasher {
    fn write(&mut self, data: &[u8]) -> Result<usize, io::Error> {
        self.0.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

#[cfg(feature = "signing")]
impl std::io::Write for Hasher {
    fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        self.0.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[repr(i8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    InvalidParamId = 40,
    InvalidMultisigHeader,
    ThresholdNotMet,
    RequireFirstNNotMet,
    LeftOverData,
    InvalidPubkeyLength,
    InvalidSignatureLength,
    ContextTooLong,
}

impl From<Error> for i8 {
    fn from(e: Error) -> i8 {
        e as i8
    }
}

pub fn construct_flag(param_id: ParamId, has_signature: bool) -> u8 {
    let value: u8 = param_id.into();
    (value << 1) | if has_signature { 1 } else { 0 }
}

pub fn destruct_flag(flag: u8) -> (ParamId, bool) {
    let has_signature = flag & 1 != 0;
    let param_id: ParamId = expect_result(
        Error::InvalidParamId,
        (flag >> 1).try_into(),
        "parse param id",
    );
    (param_id, has_signature)
}

pub fn sign_flag(flag: u8) -> u8 {
    (flag >> 1) << 1
}

/// For now a slice version suffices, later we might add one that works on
/// iterator when lazy reader is good for our use case.
pub fn iterate_public_key_with_optional_signature<F, G>(
    lock: &[u8],
    mut data_processor: F,
    length_fetcher: G,
) where
    F: FnMut(usize, ParamId, u8, &[u8], Option<&[u8]>),
    G: Fn(ParamId) -> (usize, usize),
{
    assert!(Error::InvalidMultisigHeader, lock.len() > 4);
    assert_eq!(Error::InvalidMultisigHeader, lock[0], 0x80);
    let require_first_n = lock[1];
    let mut threshold = lock[2];
    let pubkeys = lock[3];
    assert!(Error::InvalidMultisigHeader, pubkeys > 0);
    assert!(Error::InvalidMultisigHeader, threshold <= pubkeys);
    assert!(Error::InvalidMultisigHeader, threshold > 0);
    assert!(Error::InvalidMultisigHeader, require_first_n <= threshold);

    let mut i = 4;
    for pubkey_index in 0..pubkeys {
        let (param_id, has_signature) = destruct_flag(lock[i]);
        let sign_flag = sign_flag(lock[i]);
        let (public_key_length, signature_length) = length_fetcher(param_id);
        let public_key = &lock[i + 1..i + 1 + public_key_length];

        if has_signature {
            let signature =
                &lock[i + 1 + public_key_length..i + 1 + public_key_length + signature_length];
            data_processor(
                pubkey_index as usize,
                param_id,
                sign_flag,
                public_key,
                Some(signature),
            );

            assert!(Error::ThresholdNotMet, threshold > 0);
            threshold -= 1;
            i += 1 + public_key_length + signature_length;
        } else {
            data_processor(pubkey_index as usize, param_id, sign_flag, public_key, None);

            assert!(Error::RequireFirstNNotMet, pubkey_index >= require_first_n);
            i += 1 + public_key_length;
        }
    }

    assert!(Error::ThresholdNotMet, threshold == 0);
    assert!(Error::LeftOverData, i == lock.len());
}
