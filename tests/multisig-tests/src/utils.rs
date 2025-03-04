use ckb_fips205_utils::{
    ParamId,
    message::{HashAlgorithm, build_fips205_final_message},
    signing::{Sha2128F, Sha2128S, Sha2192F, Sha2256F, Shake128F, TxSigner},
};
use ckb_sphincs_utils::{SphincsPlus, sphincsplus::sphincs_plus_get_seed_size};
use ckb_testtool::bytes::Bytes;
use proptest::prelude::*;
use rand::{SeedableRng, rngs::StdRng};
use rand_core::CryptoRngCore;
use std::fmt;

// We have extensive tests covering the signature verification process
// for all different kinds of parameter sets. Here we only select a handful
// of parameter sets to speed up tests.
pub enum Signer {
    C(SphincsPlus),
    Rust128F(Sha2128F),
    Rust192F(Sha2192F),
    Rust256F(Sha2256F),
    Rust128S(Sha2128S),
    RustShake128F(Shake128F),
}

impl TxSigner for Signer {
    fn param_id(&self) -> ParamId {
        match self {
            Signer::C(_) => ckb_sphincs_utils::sphincsplus::param_id().unwrap(),
            Signer::Rust128F(s) => s.param_id(),
            Signer::Rust192F(s) => s.param_id(),
            Signer::Rust256F(s) => s.param_id(),
            Signer::Rust128S(s) => s.param_id(),
            Signer::RustShake128F(s) => s.param_id(),
        }
    }

    fn script_args_prefix(&self) -> [u8; 5] {
        match self {
            Signer::C(_) => {
                ckb_sphincs_utils::sphincsplus::single_sign_script_args_prefix().unwrap()
            }
            Signer::Rust128F(s) => s.script_args_prefix(),
            Signer::Rust192F(s) => s.script_args_prefix(),
            Signer::Rust256F(s) => s.script_args_prefix(),
            Signer::Rust128S(s) => s.script_args_prefix(),
            Signer::RustShake128F(s) => s.script_args_prefix(),
        }
    }

    fn public_key_bytes(&self) -> Bytes {
        match self {
            Signer::C(s) => Bytes::from(s.pk.clone()),
            Signer::Rust128F(s) => s.public_key_bytes(),
            Signer::Rust192F(s) => s.public_key_bytes(),
            Signer::Rust256F(s) => s.public_key_bytes(),
            Signer::Rust128S(s) => s.public_key_bytes(),
            Signer::RustShake128F(s) => s.public_key_bytes(),
        }
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        match self {
            Signer::C(s) => Bytes::from(s.sign(&build_fips205_final_message(
                HashAlgorithm::None,
                message,
                Some(&[]),
            ))),
            Signer::Rust128F(s) => s.sign_message(rng, message),
            Signer::Rust192F(s) => s.sign_message(rng, message),
            Signer::Rust256F(s) => s.sign_message(rng, message),
            Signer::Rust128S(s) => s.sign_message(rng, message),
            Signer::RustShake128F(s) => s.sign_message(rng, message),
        }
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signer::C(_) => write!(f, "sphincsplus-sha2-128f"),
            Signer::Rust128F(_) => write!(f, "fips205-sha2-128f"),
            Signer::Rust192F(_) => write!(f, "fips205-sha2-192f"),
            Signer::Rust256F(_) => write!(f, "fips205-sha2-256f"),
            Signer::Rust128S(_) => write!(f, "fips205-sha2-128s"),
            Signer::RustShake128F(_) => write!(f, "fips205-shake-128f"),
        }
    }
}

pub fn build_multisig_header(
    signers: &[Signer],
    threshold: usize,
    require_first_n: usize,
) -> Bytes {
    let threshold: u8 = threshold.try_into().expect("overflow");
    let require_first_n: u8 = require_first_n.try_into().expect("overflow");
    let pubkeys: u8 = signers.len().try_into().expect("overflow");

    vec![0x80, require_first_n, threshold, pubkeys].into()
}

pub fn build_multisig_configuration(
    signers: &[Signer],
    threshold: usize,
    require_first_n: usize,
) -> Bytes {
    let mut res = vec![];
    res.extend(&build_multisig_header(signers, threshold, require_first_n));

    for signer in signers {
        res.push(signer.param_id() as u8);
        res.extend(&signer.public_key_bytes());
    }

    Bytes::from(res)
}

pub fn signer_strategy() -> impl Strategy<Value = Signer> {
    prop_oneof![
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut seed = vec![0; unsafe { sphincs_plus_get_seed_size() } as usize];
            rng.fill(&mut seed[..]);
            Signer::C(SphincsPlus::from(&seed))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust128F(Sha2128F::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust192F(Sha2192F::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust256F(Sha2256F::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust128S(Sha2128S::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::RustShake128F(Shake128F::new(&mut rng))
        }),
    ]
}
