use super::offsets::*;
use super::sizes::*;
use ckb_fips205_utils::ParamId;

pub const PARAM_IDS_COUNT: usize = 12;

pub fn lengths(param_id: ParamId) -> (usize, usize) {
    match param_id {
        ParamId::Sha2128F => (CKB_SPHINCS_PARAM48_PK_BYTES, CKB_SPHINCS_PARAM48_SIGN_BYTES),
        ParamId::Sha2128S => (CKB_SPHINCS_PARAM49_PK_BYTES, CKB_SPHINCS_PARAM49_SIGN_BYTES),
        ParamId::Sha2192F => (CKB_SPHINCS_PARAM50_PK_BYTES, CKB_SPHINCS_PARAM50_SIGN_BYTES),
        ParamId::Sha2192S => (CKB_SPHINCS_PARAM51_PK_BYTES, CKB_SPHINCS_PARAM51_SIGN_BYTES),
        ParamId::Sha2256F => (CKB_SPHINCS_PARAM52_PK_BYTES, CKB_SPHINCS_PARAM52_SIGN_BYTES),
        ParamId::Sha2256S => (CKB_SPHINCS_PARAM53_PK_BYTES, CKB_SPHINCS_PARAM53_SIGN_BYTES),
        ParamId::Shake128F => (CKB_SPHINCS_PARAM54_PK_BYTES, CKB_SPHINCS_PARAM54_SIGN_BYTES),
        ParamId::Shake128S => (CKB_SPHINCS_PARAM55_PK_BYTES, CKB_SPHINCS_PARAM55_SIGN_BYTES),
        ParamId::Shake192F => (CKB_SPHINCS_PARAM56_PK_BYTES, CKB_SPHINCS_PARAM56_SIGN_BYTES),
        ParamId::Shake192S => (CKB_SPHINCS_PARAM57_PK_BYTES, CKB_SPHINCS_PARAM57_SIGN_BYTES),
        ParamId::Shake256F => (CKB_SPHINCS_PARAM58_PK_BYTES, CKB_SPHINCS_PARAM58_SIGN_BYTES),
        ParamId::Shake256S => (CKB_SPHINCS_PARAM59_PK_BYTES, CKB_SPHINCS_PARAM59_SIGN_BYTES),
    }
}

pub fn indices(param_id: ParamId) -> usize {
    match param_id {
        ParamId::Sha2128F => 0,
        ParamId::Sha2128S => 1,
        ParamId::Sha2192F => 2,
        ParamId::Sha2192S => 3,
        ParamId::Sha2256F => 4,
        ParamId::Sha2256S => 5,
        ParamId::Shake128F => 6,
        ParamId::Shake128S => 7,
        ParamId::Shake192F => 8,
        ParamId::Shake192S => 9,
        ParamId::Shake256F => 10,
        ParamId::Shake256S => 11,
    }
}

pub fn binary_infos(param_id: ParamId) -> (*const u32, *const u32) {
    match param_id {
        ParamId::Sha2128F => (
            (&CKB_SPHINCS_SHA2_128F_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHA2_128F_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Sha2128S => (
            (&CKB_SPHINCS_SHA2_128S_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHA2_128S_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Sha2192F => (
            (&CKB_SPHINCS_SHA2_192F_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHA2_192F_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Sha2192S => (
            (&CKB_SPHINCS_SHA2_192S_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHA2_192S_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Sha2256F => (
            (&CKB_SPHINCS_SHA2_256F_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHA2_256F_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Sha2256S => (
            (&CKB_SPHINCS_SHA2_256S_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHA2_256S_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Shake128F => (
            (&CKB_SPHINCS_SHAKE_128F_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHAKE_128F_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Shake128S => (
            (&CKB_SPHINCS_SHAKE_128S_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHAKE_128S_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Shake192F => (
            (&CKB_SPHINCS_SHAKE_192F_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHAKE_192F_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Shake192S => (
            (&CKB_SPHINCS_SHAKE_192S_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHAKE_192S_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Shake256F => (
            (&CKB_SPHINCS_SHAKE_256F_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHAKE_256F_BINARY_LENGTH) as *const u32,
        ),
        ParamId::Shake256S => (
            (&CKB_SPHINCS_SHAKE_256S_BINARY_OFFSET) as *const u32,
            (&CKB_SPHINCS_SHAKE_256S_BINARY_LENGTH) as *const u32,
        ),
    }
}
