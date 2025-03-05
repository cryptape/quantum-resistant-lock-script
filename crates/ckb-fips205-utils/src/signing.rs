use crate::{
    ckb_tx_message_all_from_mock_tx::{generate_ckb_tx_message_all, ScriptOrIndex},
    single_sign_script_args_prefix, single_sign_witness_prefix,
    verifying::lengths,
    Hasher, ParamId,
};
use ckb_gen_types::{bytes::Bytes, packed::*, prelude::*};
use fips205::traits::{SerDes, Signer, Verifier};
use rand_core::CryptoRngCore;

pub trait TxSigner {
    fn param_id(&self) -> ParamId;

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes;
    fn public_key_bytes(&self) -> Bytes;

    fn signature_length(&self) -> usize {
        lengths(self.param_id()).1
    }

    fn public_key_length(&self) -> usize {
        lengths(self.param_id()).0
    }

    fn script_args_prefix(&self) -> [u8; 5] {
        single_sign_script_args_prefix(self.param_id())
    }

    fn message_prefix(&self) -> [u8; 5] {
        single_sign_witness_prefix(self.param_id())
    }

    fn script_args(&self) -> Bytes {
        let mut hasher = Hasher::script_args_hasher();
        hasher.update(&self.script_args_prefix());
        hasher.update(&self.public_key_bytes());
        hasher.hash().to_vec().into()
    }

    /// Sign provided transaction using single-sign design
    fn sign_tx<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        tx: &Transaction,
        inputs: &[(CellOutput, Bytes)],
        first_script_group_index: usize,
    ) -> Transaction {
        let mut hasher = Hasher::message_hasher();
        generate_ckb_tx_message_all(
            tx,
            inputs,
            ScriptOrIndex::Index(first_script_group_index),
            &mut hasher,
        )
        .expect("generate message all");

        let message = hasher.hash();

        let signature = self.sign_message(rng, &message);

        let mut witnesses: Vec<_> = tx.witnesses().into_iter().collect();
        let original_witnesss = WitnessArgs::from_slice(
            &witnesses
                .get(first_script_group_index)
                .expect("indexing first group witness")
                .raw_data(),
        )
        .expect("parse witness args");

        let pubkey_len = self.public_key_length();
        let mut data = vec![0; 5 + pubkey_len + self.signature_length()];
        data[0..5].copy_from_slice(&self.message_prefix());
        data[5..pubkey_len + 5].copy_from_slice(&self.public_key_bytes());
        data[pubkey_len + 5..].copy_from_slice(&signature);

        let updated_witness = original_witnesss
            .as_builder()
            .lock(Some(Bytes::from(data)).pack())
            .build();
        witnesses[first_script_group_index] = updated_witness.as_bytes().pack();

        tx.clone()
            .as_builder()
            .witnesses(BytesVec::new_builder().set(witnesses).build())
            .build()
    }
}

pub struct Sha2128F {
    private_key: fips205::slh_dsa_sha2_128f::PrivateKey,
    public_key: fips205::slh_dsa_sha2_128f::PublicKey,
}

impl Sha2128F {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_sha2_128f::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Sha2128F {
    fn param_id(&self) -> ParamId {
        ParamId::Sha2128F
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Sha2128S {
    private_key: fips205::slh_dsa_sha2_128s::PrivateKey,
    public_key: fips205::slh_dsa_sha2_128s::PublicKey,
}

impl Sha2128S {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_sha2_128s::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Sha2128S {
    fn param_id(&self) -> ParamId {
        ParamId::Sha2128S
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Sha2192F {
    private_key: fips205::slh_dsa_sha2_192f::PrivateKey,
    public_key: fips205::slh_dsa_sha2_192f::PublicKey,
}

impl Sha2192F {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_sha2_192f::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Sha2192F {
    fn param_id(&self) -> ParamId {
        ParamId::Sha2192F
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Sha2192S {
    private_key: fips205::slh_dsa_sha2_192s::PrivateKey,
    public_key: fips205::slh_dsa_sha2_192s::PublicKey,
}

impl Sha2192S {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_sha2_192s::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Sha2192S {
    fn param_id(&self) -> ParamId {
        ParamId::Sha2192S
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Sha2256F {
    private_key: fips205::slh_dsa_sha2_256f::PrivateKey,
    public_key: fips205::slh_dsa_sha2_256f::PublicKey,
}

impl Sha2256F {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_sha2_256f::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Sha2256F {
    fn param_id(&self) -> ParamId {
        ParamId::Sha2256F
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Sha2256S {
    private_key: fips205::slh_dsa_sha2_256s::PrivateKey,
    public_key: fips205::slh_dsa_sha2_256s::PublicKey,
}

impl Sha2256S {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_sha2_256s::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Sha2256S {
    fn param_id(&self) -> ParamId {
        ParamId::Sha2256S
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Shake128F {
    private_key: fips205::slh_dsa_shake_128f::PrivateKey,
    public_key: fips205::slh_dsa_shake_128f::PublicKey,
}

impl Shake128F {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_shake_128f::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Shake128F {
    fn param_id(&self) -> ParamId {
        ParamId::Shake128F
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Shake128S {
    private_key: fips205::slh_dsa_shake_128s::PrivateKey,
    public_key: fips205::slh_dsa_shake_128s::PublicKey,
}

impl Shake128S {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_shake_128s::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Shake128S {
    fn param_id(&self) -> ParamId {
        ParamId::Shake128S
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Shake192F {
    private_key: fips205::slh_dsa_shake_192f::PrivateKey,
    public_key: fips205::slh_dsa_shake_192f::PublicKey,
}

impl Shake192F {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_shake_192f::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Shake192F {
    fn param_id(&self) -> ParamId {
        ParamId::Shake192F
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Shake192S {
    private_key: fips205::slh_dsa_shake_192s::PrivateKey,
    public_key: fips205::slh_dsa_shake_192s::PublicKey,
}

impl Shake192S {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_shake_192s::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Shake192S {
    fn param_id(&self) -> ParamId {
        ParamId::Shake192S
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Shake256F {
    private_key: fips205::slh_dsa_shake_256f::PrivateKey,
    public_key: fips205::slh_dsa_shake_256f::PublicKey,
}

impl Shake256F {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_shake_256f::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Shake256F {
    fn param_id(&self) -> ParamId {
        ParamId::Shake256F
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}

pub struct Shake256S {
    private_key: fips205::slh_dsa_shake_256s::PrivateKey,
    public_key: fips205::slh_dsa_shake_256s::PublicKey,
}

impl Shake256S {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (public_key, private_key) =
            fips205::slh_dsa_shake_256s::try_keygen_with_rng(rng).expect("keygen");
        Self {
            public_key,
            private_key,
        }
    }
}

impl TxSigner for Shake256S {
    fn param_id(&self) -> ParamId {
        ParamId::Shake256S
    }

    fn public_key_bytes(&self) -> Bytes {
        self.public_key.clone().into_bytes().to_vec().into()
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        let sig = self
            .private_key
            .try_sign_with_rng(rng, message, &[], true)
            .expect("sign");
        assert!(self.public_key.verify(message, &sig, &[]));
        sig.to_vec().into()
    }
}
