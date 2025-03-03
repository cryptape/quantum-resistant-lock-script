use super::offsets::*;
use super::sizes::*;
use ckb_fips205_utils::ParamId;

pub const PARAM_IDS_COUNT: usize = 12;

pub fn lengths(param_id: ParamId) -> (usize, usize) {
    match param_id {
        ParamId::Sha2128F => (CKB_SPHINCS_PARAM1_PK_BYTES, CKB_SPHINCS_PARAM1_SIGN_BYTES),
        ParamId::Sha2128S => (CKB_SPHINCS_PARAM2_PK_BYTES, CKB_SPHINCS_PARAM2_SIGN_BYTES),
        ParamId::Sha2192F => (CKB_SPHINCS_PARAM3_PK_BYTES, CKB_SPHINCS_PARAM3_SIGN_BYTES),
        ParamId::Sha2192S => (CKB_SPHINCS_PARAM4_PK_BYTES, CKB_SPHINCS_PARAM4_SIGN_BYTES),
        ParamId::Sha2256F => (CKB_SPHINCS_PARAM5_PK_BYTES, CKB_SPHINCS_PARAM5_SIGN_BYTES),
        ParamId::Sha2256S => (CKB_SPHINCS_PARAM6_PK_BYTES, CKB_SPHINCS_PARAM6_SIGN_BYTES),
        ParamId::Shake128F => (CKB_SPHINCS_PARAM7_PK_BYTES, CKB_SPHINCS_PARAM7_SIGN_BYTES),
        ParamId::Shake128S => (CKB_SPHINCS_PARAM8_PK_BYTES, CKB_SPHINCS_PARAM8_SIGN_BYTES),
        ParamId::Shake192F => (CKB_SPHINCS_PARAM9_PK_BYTES, CKB_SPHINCS_PARAM9_SIGN_BYTES),
        ParamId::Shake192S => (CKB_SPHINCS_PARAM10_PK_BYTES, CKB_SPHINCS_PARAM10_SIGN_BYTES),
        ParamId::Shake256F => (CKB_SPHINCS_PARAM11_PK_BYTES, CKB_SPHINCS_PARAM11_SIGN_BYTES),
        ParamId::Shake256S => (CKB_SPHINCS_PARAM12_PK_BYTES, CKB_SPHINCS_PARAM12_SIGN_BYTES),
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
