use crate::types::HashAlgorithm;
use sha2::Digest;

pub fn build_fips205_final_message(
    algo: HashAlgorithm,
    message: &[u8],
    context: Option<&[u8]>,
) -> Vec<u8> {
    let prehash = if algo == HashAlgorithm::None {
        0u8
    } else {
        1u8
    };

    let context_prefix = match context {
        Some(context) => {
            assert!(context.len() <= 255);
            let mut res = vec![0u8; context.len() + 2];
            res[0] = prehash;
            res[1] = context.len() as u8;
            res[2..].copy_from_slice(context);
            res
        }
        None => vec![],
    };

    let oid = match algo {
        HashAlgorithm::None => vec![],
        HashAlgorithm::Sha2224 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
        ],
        HashAlgorithm::Sha2256 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
        HashAlgorithm::Sha2384 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        ],
        HashAlgorithm::Sha2512 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ],
        HashAlgorithm::Sha2512224 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
        ],
        HashAlgorithm::Sha2512256 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
        ],
        HashAlgorithm::Sha3224 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
        ],
        HashAlgorithm::Sha3256 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
        ],
        HashAlgorithm::Sha3384 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
        ],
        HashAlgorithm::Sha3512 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A,
        ],
        HashAlgorithm::Shake128 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
        ],
        HashAlgorithm::Shake256 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
        ],
    };

    let hashed_message = match algo {
        HashAlgorithm::None => message.to_vec(),
        HashAlgorithm::Sha2224 => {
            let mut hasher = sha2::Sha224::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha2256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha2384 => {
            let mut hasher = sha2::Sha384::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha2512 => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha2512224 => {
            let mut hasher = sha2::Sha512_224::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha2512256 => {
            let mut hasher = sha2::Sha512_256::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3224 => {
            let mut hasher = sha3::Sha3_224::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3256 => {
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3384 => {
            let mut hasher = sha3::Sha3_384::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3512 => {
            let mut hasher = sha3::Sha3_512::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Shake128 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut hasher = sha3::Shake128::default();
            hasher.update(message);
            let mut reader = hasher.finalize_xof();
            let mut res = vec![0u8; 32];
            reader.read(&mut res);
            res
        }
        HashAlgorithm::Shake256 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut hasher = sha3::Shake256::default();
            hasher.update(message);
            let mut reader = hasher.finalize_xof();
            let mut res = vec![0u8; 64];
            reader.read(&mut res);
            res
        }
    };

    [context_prefix, oid, hashed_message].concat()
}
