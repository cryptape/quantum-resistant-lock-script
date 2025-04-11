use crate::Loader;
use ckb_fips205_utils::signing::*;
use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        packed::*,
        prelude::*,
    },
    context::Context,
};
use proptest::prelude::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_core::CryptoRngCore;
use std::path::Path;

const C_NAME: &'static str = "c-sphincs-all-in-one-lock";
const HYBRID_NAME: &'static str = "hybrid-sphincs-all-in-one-lock";
const RUST_NAME: &'static str = "sphincs-all-in-one-lock";

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 30, .. ProptestConfig::default()
    })]

    #[test]
    fn test_c_valid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128F::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2128S::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192F::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2192S::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128F::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake128S::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 15, .. ProptestConfig::default()
    })]

    #[test]
    fn test_c_valid_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256F::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Sha2256S::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192F::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake192S::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256F::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256F::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256F::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }

    #[test]
    fn test_c_valid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(C_NAME, signer, rng);
    }

    #[test]
    fn test_rust_valid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(RUST_NAME, signer, rng);
    }

    #[test]
    fn test_hybrid_valid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signer = Shake256S::new(&mut rng);
        _test_valid_tx(HYBRID_NAME, signer, rng);
    }
}

proptest! {
    // Since it's really signature generation that takes time, for invalid tx tests we will
    // generate fewer signatures, but tweak the same tx multiple times to speed things up.
    #![proptest_config(ProptestConfig {
        cases: 5, .. ProptestConfig::default()
    })]

    #[test]
    fn test_invalid_prefix_c_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_c_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_c_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_c_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_c_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_c_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_c_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_c_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_c_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_c_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_c_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_c_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_c_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_c_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_c_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_c_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(C_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_rust_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_rust_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_rust_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_rust_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_rust_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_rust_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_rust_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_rust_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_rust_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_rust_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_rust_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_rust_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_rust_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_rust_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_rust_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_rust_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(RUST_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_hybrid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_sha2_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_hybrid_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_sha2_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_hybrid_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_sha2_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_hybrid_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_sha2_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_hybrid_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_sha2_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_hybrid_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_sha2_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Sha2256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_hybrid_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_shake_128f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_hybrid_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_shake_128s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake128S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_hybrid_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_shake_192f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_hybrid_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_shake_192s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake192S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }


    #[test]
    fn test_invalid_prefix_hybrid_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_shake_256f(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256F::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_prefix_hybrid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..10 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(0..5)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_pubkey_hybrid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..15 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                lock[rng2.gen_range(5..5 + public_key_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_signature_hybrid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let public_key_length = signer.public_key_length();
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..20 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
                let lock_length = lock.len();
                lock[rng2.gen_range(5 + public_key_length..lock_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().lock(Some(Bytes::from(lock)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_tx_hybrid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = {
                let mut output_data: Vec<u8> = valid_tx.outputs_data().get(0).unwrap().unpack();
                let output_data_len = output_data.len();
                output_data[rng2.gen_range(0..output_data_len)] ^= 1 << rng2.gen_range(0..8);
                valid_tx.as_advanced_builder()
                    .set_outputs_data(vec![Bytes::from(output_data).pack()])
                    .build()
            };

            _run_invalid_tx(&context, invalid_tx);
        }
    }

    #[test]
    fn test_invalid_witness_hybrid_shake_256s(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut rng2 = StdRng::seed_from_u64(rng.gen());

        let signer = Shake256S::new(&mut rng);
        let (context, valid_tx) = _build_valid_tx(HYBRID_NAME, signer, rng);

        for _ in 0..5 {
            let invalid_tx = _tweak_first_witness(&valid_tx, |witness_args| {
                let mut input_type: Vec<u8> = witness_args.input_type().to_opt().unwrap().unpack();
                let input_type_length = input_type.len();
                input_type[rng2.gen_range(0..input_type_length)] ^= 1 << rng2.gen_range(0..8);
                witness_args.as_builder().input_type(Some(Bytes::from(input_type)).pack()).build()
            });

            _run_invalid_tx(&context, invalid_tx);
        }
    }
}

fn _tweak_first_witness<F>(tx: &TransactionView, mut f: F) -> TransactionView
where
    F: FnMut(WitnessArgs) -> WitnessArgs,
{
    let mut witnesses: Vec<_> = tx.witnesses().into_iter().collect();
    let first_witness =
        WitnessArgs::from_slice(&witnesses[0].raw_data()).expect("parse witness args");
    witnesses[0] = f(first_witness).as_bytes().pack();

    tx.as_advanced_builder().set_witnesses(witnesses).build()
}

fn _save_tx_if_requested(context: &Context, tx: &TransactionView) {
    if let Some(path) = std::env::var_os("DUMP_TXS_PATH") {
        if let Ok(s) = std::env::var("DUMP_PROBABILITY") {
            let prob = u16::from_str_radix(&s, 10).expect("parse dump probability");
            if prob > 256 {
                panic!("DUMP_PROBABILITY can only range from 0 to 256!");
            }
            let val = tx.hash().nth0().as_slice()[0] as u16;
            if val < prob {
                let directory = Path::new(&path);
                std::fs::create_dir_all(&directory).expect("mkdir -p");

                let path = directory.join(format!("0x{:x}.json", tx.hash()));
                let mock_tx = context.dump_tx(&tx).expect("dump failed tx");
                let json = serde_json::to_string_pretty(&mock_tx).expect("json");
                std::fs::write(path, json).expect("write");
            }
        }
    }
}

fn _run_invalid_tx(context: &Context, tx: TransactionView) {
    _save_tx_if_requested(context, &tx);

    let e = context.verify_tx(&tx, 200_000_000).unwrap_err();
    assert!(!format!("{}", e).contains("ExceededMaximumCycles"));
}

fn _test_valid_tx<S: TxSigner, R: Rng + CryptoRngCore>(name: &'static str, signer: S, rng: R) {
    let (context, tx) = _build_valid_tx(name, signer, rng);

    _save_tx_if_requested(&context, &tx);

    let cycles = context
        .verify_tx(&tx, 200_000_000)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

fn _build_valid_tx<S: TxSigner, R: Rng + CryptoRngCore>(
    name: &'static str,
    signer: S,
    mut rng: R,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary(name);

    let out_point = context.deploy_cell(contract_bin);

    let lock_script = context
        .build_script(&out_point, signer.script_args())
        .expect("script");

    let input_cell_data = gen_data(&mut rng, 1, 1000);
    let input_cell_output = CellOutput::new_builder()
        .capacity((2000u64 * 100000000u64).pack())
        .lock(lock_script.clone())
        .build();
    let input_out_point = context.create_cell(input_cell_output.clone(), input_cell_data.clone());
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output_cell_data = gen_data(&mut rng, 1, 1000);
    let output_cell_output = CellOutput::new_builder()
        .capacity((1999u64 * 100000000u64).pack())
        .lock(lock_script.clone())
        .build();

    let witness_args = WitnessArgs::new_builder()
        .input_type(Some(gen_data(&mut rng, 1, 200)).pack())
        .output_type(Some(gen_data(&mut rng, 1, 200)).pack())
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output_cell_output)
        .output_data(output_cell_data.pack())
        .witness(witness_args.as_bytes().pack())
        .build();
    let unsigned_tx = context.complete_tx(tx);
    let signed_tx = signer.sign_tx(
        &mut rng,
        &unsigned_tx.data(),
        &[(input_cell_output, input_cell_data)],
        0,
    );

    (context, signed_tx.into_view())
}

fn gen_data<R: Rng>(rng: &mut R, min: usize, max: usize) -> Bytes {
    let len = rng.gen_range(min..=max);
    let mut data = vec![0; len];
    rng.fill(&mut data[..]);
    data.into()
}
