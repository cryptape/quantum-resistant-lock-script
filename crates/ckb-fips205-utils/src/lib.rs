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

const MULTISIG_RESERVED_FIELD_VALUE: u8 = 0x80;
const MULTISIG_PARAMS_ID_MASK: u8 = 0x7F;
const MULTISIG_SIG_MASK: u8 = 1u8 << 7;

/// For now a slice version suffices, later we might add one that works on
/// iterator when lazy reader is good for our use case.
pub fn iterate_public_key_with_optional_signature<F, G>(
    lock: &[u8],
    mut data_processor: F,
    length_fetcher: G,
) where
    F: FnMut(usize, ParamId, &[u8], Option<&[u8]>),
    G: Fn(ParamId) -> (usize, usize),
{
    assert!(lock.len() > 4);
    assert_eq!(lock[0], MULTISIG_RESERVED_FIELD_VALUE);
    let require_first_n = lock[1];
    let mut threshold = lock[2];
    let pubkeys = lock[3];
    assert!(pubkeys > 0);
    assert!(threshold <= pubkeys);
    assert!(threshold > 0);
    assert!(require_first_n <= threshold);

    let mut i = 4;
    for pubkey_index in 0..pubkeys {
        let id = lock[i];
        let param_id: ParamId = (id & MULTISIG_PARAMS_ID_MASK)
            .try_into()
            .expect("parse param id");
        let (public_key_length, signature_length) = length_fetcher(param_id);
        let public_key = &lock[i + 1..i + 1 + public_key_length];

        if (id & MULTISIG_SIG_MASK) != 0 {
            let signature =
                &lock[i + 1 + public_key_length..i + 1 + public_key_length + signature_length];
            data_processor(pubkey_index as usize, param_id, public_key, Some(signature));

            assert!(threshold > 0);
            threshold -= 1;
            i += 1 + public_key_length + signature_length;
        } else {
            data_processor(pubkey_index as usize, param_id, public_key, None);

            assert!(pubkey_index >= require_first_n);
            i += 1 + public_key_length;
        }
    }

    assert!(threshold == 0);
    assert!(i == lock.len());
}
