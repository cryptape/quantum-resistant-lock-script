#![cfg_attr(not(any(feature = "signing", feature = "serde", test)), no_std)]

#[cfg(feature = "signing")]
pub mod ckb_tx_message_all_from_mock_tx;
pub mod ckb_tx_message_all_in_ckb_vm;
#[cfg(feature = "signing")]
pub mod signing;

use ckb_hash::{Blake2b, Blake2bBuilder};
use ckb_rust_std::io;
use fips205::traits::{SerDes, Verifier};
#[cfg(feature = "serde")]
use serde_string_enum::{DeserializeLabeledStringEnum, SerializeLabeledStringEnum};

// TODO: this should be generated from params.txs file
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

pub fn lengths(param_id: ParamId) -> (usize, usize) {
    match param_id {
        ParamId::Sha2128F => (
            fips205::slh_dsa_sha2_128f::PK_LEN,
            fips205::slh_dsa_sha2_128f::SIG_LEN,
        ),
        ParamId::Sha2128S => (
            fips205::slh_dsa_sha2_128s::PK_LEN,
            fips205::slh_dsa_sha2_128s::SIG_LEN,
        ),
        ParamId::Sha2192F => (
            fips205::slh_dsa_sha2_192f::PK_LEN,
            fips205::slh_dsa_sha2_192f::SIG_LEN,
        ),
        ParamId::Sha2192S => (
            fips205::slh_dsa_sha2_192s::PK_LEN,
            fips205::slh_dsa_sha2_192s::SIG_LEN,
        ),
        ParamId::Sha2256F => (
            fips205::slh_dsa_sha2_256f::PK_LEN,
            fips205::slh_dsa_sha2_256f::SIG_LEN,
        ),
        ParamId::Sha2256S => (
            fips205::slh_dsa_sha2_256s::PK_LEN,
            fips205::slh_dsa_sha2_256s::SIG_LEN,
        ),
        ParamId::Shake128F => (
            fips205::slh_dsa_shake_128f::PK_LEN,
            fips205::slh_dsa_shake_128f::SIG_LEN,
        ),
        ParamId::Shake128S => (
            fips205::slh_dsa_shake_128s::PK_LEN,
            fips205::slh_dsa_shake_128s::SIG_LEN,
        ),
        ParamId::Shake192F => (
            fips205::slh_dsa_shake_192f::PK_LEN,
            fips205::slh_dsa_shake_192f::SIG_LEN,
        ),
        ParamId::Shake192S => (
            fips205::slh_dsa_shake_192s::PK_LEN,
            fips205::slh_dsa_shake_192s::SIG_LEN,
        ),
        ParamId::Shake256F => (
            fips205::slh_dsa_shake_256f::PK_LEN,
            fips205::slh_dsa_shake_256f::SIG_LEN,
        ),
        ParamId::Shake256S => (
            fips205::slh_dsa_shake_256s::PK_LEN,
            fips205::slh_dsa_shake_256s::SIG_LEN,
        ),
    }
}

pub fn verify(param_id: ParamId, public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    match param_id {
        ParamId::Sha2128F => {
            use fips205::slh_dsa_sha2_128f as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2128S => {
            use fips205::slh_dsa_sha2_128s as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2192F => {
            use fips205::slh_dsa_sha2_192f as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2192S => {
            use fips205::slh_dsa_sha2_192s as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2256F => {
            use fips205::slh_dsa_sha2_256f as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2256S => {
            use fips205::slh_dsa_sha2_256s as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake128F => {
            use fips205::slh_dsa_shake_128f as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake128S => {
            use fips205::slh_dsa_shake_128s as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake192F => {
            use fips205::slh_dsa_shake_192f as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake192S => {
            use fips205::slh_dsa_shake_192s as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake256F => {
            use fips205::slh_dsa_shake_256f as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake256S => {
            use fips205::slh_dsa_shake_256s as slh;

            assert_eq!(public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
    }
}
