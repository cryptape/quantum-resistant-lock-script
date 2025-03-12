use crate::{Error, ParamId};
use ckb_std::assert_eq;
use fips205::traits::{SerDes, Verifier};

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

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2128S => {
            use fips205::slh_dsa_sha2_128s as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2192F => {
            use fips205::slh_dsa_sha2_192f as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2192S => {
            use fips205::slh_dsa_sha2_192s as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2256F => {
            use fips205::slh_dsa_sha2_256f as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Sha2256S => {
            use fips205::slh_dsa_sha2_256s as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake128F => {
            use fips205::slh_dsa_shake_128f as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake128S => {
            use fips205::slh_dsa_shake_128s as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake192F => {
            use fips205::slh_dsa_shake_192f as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake192S => {
            use fips205::slh_dsa_shake_192s as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake256F => {
            use fips205::slh_dsa_shake_256f as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
        ParamId::Shake256S => {
            use fips205::slh_dsa_shake_256s as slh;

            assert_eq!(Error::InvalidPubkeyLength, public_key.len(), slh::PK_LEN);
            let public_key = {
                let mut data = [0u8; slh::PK_LEN];
                data.copy_from_slice(public_key);
                slh::PublicKey::try_from_bytes(&data).expect("parse public key")
            };
            assert_eq!(Error::InvalidSignatureLength, signature.len(), slh::SIG_LEN);
            let signature = {
                let mut data = [0u8; slh::SIG_LEN];
                data.copy_from_slice(signature);
                data
            };
            public_key.verify(message, &signature, &[])
        }
    }
}
