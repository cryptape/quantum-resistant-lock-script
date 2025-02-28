use ckb_fips205_utils::ParamId;

#[link(name = "sphincsplus", kind = "static")]
extern "C" {
    // uint32_t sphincs_plus_get_pk_size();
    fn sphincs_plus_get_pk_size() -> u32;

    // uint32_t sphincs_plus_get_sk_size();
    fn sphincs_plus_get_sk_size() -> u32;

    // uint32_t sphincs_plus_get_sign_size();
    fn sphincs_plus_get_sign_size() -> u32;

    // int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk);
    fn sphincs_plus_generate_keypair(pk: *mut u8, sk: *mut u8) -> i32;

    // int sphincs_plus_sign(uint8_t *message, uint32_t message_size, uint8_t *sk, uint8_t *out_sign);
    fn sphincs_plus_sign(
        message: *const u8,
        message_size: u32,
        sk: *const u8,
        out_sign: *mut u8,
    ) -> i32;

    // int sphincs_plus_verify(uint8_t *sign, uint32_t sign_size, uint8_t *message,
    //                         uint32_t message_size, uint8_t *pubkey,
    //                         uint32_t pubkey_size);
    fn sphincs_plus_verify(
        sign: *const u8,
        sign_size: u32,
        message: *const u8,
        message_sizse: u32,
        pk: *const u8,
        pk_size: u32,
    ) -> i32;
}

pub struct SphincsPlus {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

impl Default for SphincsPlus {
    fn default() -> Self {
        Self::new()
    }
}

impl SphincsPlus {
    pub fn get_pk_len(&self) -> usize {
        unsafe { sphincs_plus_get_pk_size() as usize }
    }

    pub fn get_sk_len(&self) -> usize {
        unsafe { sphincs_plus_get_sk_size() as usize }
    }

    pub fn get_sign_len(&self) -> usize {
        unsafe { sphincs_plus_get_sign_size() as usize }
    }

    pub fn new() -> Self {
        let mut s = Self {
            pk: Vec::new(),
            sk: Vec::new(),
        };
        unsafe {
            s.pk.resize(sphincs_plus_get_pk_size() as usize, 0);
            s.sk.resize(sphincs_plus_get_sk_size() as usize, 0);
        }

        let ret = unsafe { sphincs_plus_generate_keypair(s.pk.as_mut_ptr(), s.sk.as_mut_ptr()) };
        if ret != 0 {
            panic!("gen keypair failed");
        }

        s
    }

    #[cfg(feature = "serialize_key")]
    pub fn deserialize_key(s: &str) -> Self {
        use base64::prelude::*;
        let buf = BASE64_STANDARD.decode(s).expect("decode base64");

        let pk_len = unsafe { sphincs_plus_get_pk_size() as usize };
        let sk_len = unsafe { sphincs_plus_get_sk_size() as usize };
        assert_eq!(buf.len(), pk_len + sk_len);

        Self {
            pk: buf[0..pk_len].to_vec(),
            sk: buf[pk_len..].to_vec(),
        }
    }

    #[cfg(feature = "serialize_key")]
    pub fn serialize_key(&self) -> String {
        let buf_len = self.pk.len() + self.sk.len();
        let mut buf = Vec::with_capacity(buf_len);

        buf.resize(buf_len, 0);

        buf[0..self.pk.len()].copy_from_slice(&self.pk);
        buf[self.pk.len()..].copy_from_slice(&self.sk);

        use base64::prelude::*;
        BASE64_STANDARD.encode(&buf)
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut s = vec![0; self.get_sign_len()];

        let ret = unsafe {
            sphincs_plus_sign(
                msg.as_ptr(),
                msg.len() as u32,
                self.sk.as_ptr(),
                s.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0);

        s
    }

    pub fn verify(&self, msg: &[u8], sign: &[u8]) -> bool {
        let mut sm = Vec::new();
        sm.resize(32, 0xFF);

        unsafe {
            sphincs_plus_verify(
                sign.as_ptr(),
                sign.len() as u32,
                msg.as_ptr(),
                msg.len() as u32,
                self.pk.as_ptr(),
                self.pk.len() as u32,
            ) == 0
        }
    }
}

#[inline]
pub fn param_id() -> Option<ParamId> {
    if cfg!(all(
        feature = "sha2",
        feature = "hash_128",
        feature = "hash_options_f",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Sha2128F);
    }

    if cfg!(all(
        feature = "sha2",
        feature = "hash_128",
        feature = "hash_options_s",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Sha2128S);
    }

    if cfg!(all(
        feature = "sha2",
        feature = "hash_192",
        feature = "hash_options_f",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Sha2192F);
    }

    if cfg!(all(
        feature = "sha2",
        feature = "hash_192",
        feature = "hash_options_s",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Sha2192S);
    }

    if cfg!(all(
        feature = "sha2",
        feature = "hash_256",
        feature = "hash_options_f",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Sha2256F);
    }

    if cfg!(all(
        feature = "sha2",
        feature = "hash_256",
        feature = "hash_options_s",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Sha2256S);
    }

    if cfg!(all(
        feature = "shake",
        feature = "hash_128",
        feature = "hash_options_f",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Shake128F);
    }

    if cfg!(all(
        feature = "shake",
        feature = "hash_128",
        feature = "hash_options_s",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Shake128S);
    }

    if cfg!(all(
        feature = "shake",
        feature = "hash_192",
        feature = "hash_options_f",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Shake192F);
    }

    if cfg!(all(
        feature = "shake",
        feature = "hash_192",
        feature = "hash_options_s",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Shake192S);
    }

    if cfg!(all(
        feature = "shake",
        feature = "hash_256",
        feature = "hash_options_f",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Shake256F);
    }

    if cfg!(all(
        feature = "shake",
        feature = "hash_256",
        feature = "hash_options_s",
        feature = "thashes_simple"
    )) {
        return Some(ParamId::Shake256S);
    }

    None
}

#[inline]
pub fn single_sign_script_args_prefix() -> Option<[u8; 5]> {
    param_id().map(ckb_fips205_utils::single_sign_script_args_prefix)
}

#[inline]
pub fn single_sign_witness_prefix() -> Option<[u8; 5]> {
    param_id().map(ckb_fips205_utils::single_sign_witness_prefix)
}
