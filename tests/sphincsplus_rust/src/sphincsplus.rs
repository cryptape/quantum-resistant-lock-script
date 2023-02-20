use num_enum::IntoPrimitive;

#[link(name = "sphincsplus", kind = "static")]
extern "C" {
    // uint32_t sphincs_plus_get_pk_size();
    fn sphincs_plus_get_pk_size() -> u32;

    // uint32_t sphincs_plus_get_sk_size();
    fn sphincs_plus_get_sk_size() -> u32;

    // uint32_t sphincs_plus_get_sign_size();
    pub fn sphincs_plus_get_sign_size() -> u32;

    // int sphincs_plus_init(crypto_type type);
    fn sphincs_plus_init(hash_type: u32) -> i32;

    // int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk);
    fn sphincs_plus_generate_keypair(pk: *mut u8, sk: *mut u8) -> i32;

    // int sphincs_plus_sign(uint8_t *message, uint8_t *sk, uint8_t *out_sign);
    fn sphincs_plus_sign(msg: *const u8, sk: *const u8, out_sign: *mut u8) -> i32;

    // int sphincs_plus_verify(uint8_t *sign, uint8_t *message, uint8_t *pubkey);
    fn sphincs_plus_verify(
        sign: *const u8,
        sign_len: u32,
        msg: *const u8,
        msg_len: u32,
        pk: *const u8,
        pk_len: u32,
    ) -> i32;
}

pub struct SphincsPlus {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

#[derive(IntoPrimitive, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum CryptoType {
    Shake128sRobust = 1,
    Shake128sSimple,
    Shake128fRobust,
    Shake128fSimple,

    Shake192sRobust,
    Shake192sSimple,
    Shake192fRobust,
    Shake192fSimple,

    Shake256sRobust,
    Shake256sSimple,
    Shake256fRobust,
    Shake256fSimple,

    // sha2
    Sha2128sRobust,
    Sha2128sSimple,
    Sha2128fRobust,
    Sha2128fSimple,

    Sha2192sRobust,
    Sha2192sSimple,
    Sha2192fRobust,
    Sha2192fSimple,

    Sha2256sRobust,
    Sha2256sSimple,
    Sha2256fRobust,
    Sha2256fSimple,

    // haraka
    Haraka128sRobust,
    Haraka128sSimple,
    Haraka128fRobust,
    Haraka128fSimple,

    Haraka192sRobust,
    Haraka192sSimple,
    Haraka192fRobust,
    Haraka192fSimple,

    Haraka256sRobust,
    Haraka256sSimple,
    Haraka256fRobust,
    Haraka256fSimple,

    ErrorHashMode,
}

impl CryptoType {
    pub fn get_all() -> Vec<Self> {
        vec![
            CryptoType::Shake128sRobust,
            CryptoType::Shake128sSimple,
            CryptoType::Shake128fRobust,
            CryptoType::Shake128fSimple,
            CryptoType::Shake192sRobust,
            CryptoType::Shake192sSimple,
            CryptoType::Shake192fRobust,
            CryptoType::Shake192fSimple,
            CryptoType::Shake256sRobust,
            CryptoType::Shake256sSimple,
            CryptoType::Shake256fRobust,
            CryptoType::Shake256fSimple,
            CryptoType::Sha2128sRobust,
            CryptoType::Sha2128sSimple,
            CryptoType::Sha2128fRobust,
            CryptoType::Sha2128fSimple,
            CryptoType::Sha2192sRobust,
            CryptoType::Sha2192sSimple,
            CryptoType::Sha2192fRobust,
            CryptoType::Sha2192fSimple,
            CryptoType::Sha2256sRobust,
            CryptoType::Sha2256sSimple,
            CryptoType::Sha2256fRobust,
            CryptoType::Sha2256fSimple,
            CryptoType::Haraka128sRobust,
            CryptoType::Haraka128sSimple,
            CryptoType::Haraka128fRobust,
            CryptoType::Haraka128fSimple,
            CryptoType::Haraka192sRobust,
            CryptoType::Haraka192sSimple,
            CryptoType::Haraka192fRobust,
            CryptoType::Haraka192fSimple,
            CryptoType::Haraka256sRobust,
            CryptoType::Haraka256sSimple,
            CryptoType::Haraka256fRobust,
            CryptoType::Haraka256fSimple,
        ]
    }
}

impl SphincsPlus {
    pub fn get_pk_len() -> usize {
        unsafe { sphincs_plus_get_pk_size() as usize }
    }

    pub fn get_sk_len() -> usize {
        unsafe { sphincs_plus_get_sk_size() as usize }
    }

    pub fn get_sign_len() -> usize {
        unsafe { sphincs_plus_get_sign_size() as usize }
    }

    pub fn new(t: CryptoType) -> Self {
        let ret = unsafe { sphincs_plus_init(t.into()) };
        assert!(ret == 0);

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

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.resize(SphincsPlus::get_sign_len(), 0);

        let ret = unsafe { sphincs_plus_sign(msg.as_ptr(), self.sk.as_ptr(), s.as_mut_ptr()) };
        assert_eq!(ret, 0);

        s
    }

    pub fn verify(&self, msg: &[u8], sign: &[u8]) -> Result<(), ()> {
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
            );
        }

        Ok(())
    }
}
