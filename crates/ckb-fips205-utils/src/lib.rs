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

#[cfg(feature = "serde")]
use serde_string_enum::{DeserializeLabeledStringEnum, SerializeLabeledStringEnum};

/// Sole truth for param ID definitions in current repository
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(SerializeLabeledStringEnum, DeserializeLabeledStringEnum)
)]
pub enum ParamId {
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-128f")]
    Sha2128F,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-128s")]
    Sha2128S,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-192f")]
    Sha2192F,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-192s")]
    Sha2192S,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-256f")]
    Sha2256F,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHA2-256s")]
    Sha2256S,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-128f")]
    Shake128F,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-128s")]
    Shake128S,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-192f")]
    Shake192F,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-192s")]
    Shake192S,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-256f")]
    Shake256F,
    #[cfg_attr(feature = "serde", string = "SLH-DSA-SHAKE-256s")]
    Shake256S,
}

impl From<ParamId> for u8 {
    fn from(id: ParamId) -> u8 {
        match id {
            ParamId::Sha2128F => 1,
            ParamId::Sha2128S => 2,
            ParamId::Sha2192F => 3,
            ParamId::Sha2192S => 4,
            ParamId::Sha2256F => 5,
            ParamId::Sha2256S => 6,
            ParamId::Shake128F => 7,
            ParamId::Shake128S => 8,
            ParamId::Shake192F => 9,
            ParamId::Shake192S => 10,
            ParamId::Shake256F => 11,
            ParamId::Shake256S => 12,
        }
    }
}

impl TryFrom<u8> for ParamId {
    // We don't really need an error here, the only possible
    // case where it when wrong is when an invalid param ID
    // is used.
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ParamId::Sha2128F),
            2 => Ok(ParamId::Sha2128S),
            3 => Ok(ParamId::Sha2192F),
            4 => Ok(ParamId::Sha2192S),
            5 => Ok(ParamId::Sha2256F),
            6 => Ok(ParamId::Sha2256S),
            7 => Ok(ParamId::Shake128F),
            8 => Ok(ParamId::Shake128S),
            9 => Ok(ParamId::Shake192F),
            10 => Ok(ParamId::Shake192S),
            11 => Ok(ParamId::Shake256F),
            12 => Ok(ParamId::Shake256S),
            _ => Err(()),
        }
    }
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
