#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(feature = "signing")]
pub mod ckb_tx_message_all_from_mock_tx;
#[cfg(feature = "signing")]
pub mod signing;

#[cfg(feature = "verifying")]
pub mod ckb_tx_message_all_in_ckb_vm;
#[cfg(feature = "verifying")]
pub mod verifying;

#[cfg(feature = "message")]
pub mod message;

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
    Sha2128F = 1,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-128s")]
    Sha2128S = 2,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-192f")]
    Sha2192F = 3,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-192s")]
    Sha2192S = 4,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-256f")]
    Sha2256F = 5,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-256s")]
    Sha2256S = 6,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-128f")]
    Shake128F = 7,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-128s")]
    Shake128S = 8,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-192f")]
    Shake192F = 9,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-192s")]
    Shake192S = 10,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-256f")]
    Shake256F = 11,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-256s")]
    Shake256S = 12,
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
    [0x80, 0x01, 0x01, 0x01, param_id.into()]
}

pub fn single_sign_witness_prefix(param_id: ParamId) -> [u8; 5] {
    let mut prefix = single_sign_script_args_prefix(param_id);
    prefix[4] |= 0x80;
    prefix
}
