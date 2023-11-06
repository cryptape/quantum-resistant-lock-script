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

    // int sphincs_plus_sign(uint8_t *message, uint8_t *sk, uint8_t *out_sign);
    fn sphincs_plus_sign(message: *const u8, sk: *const u8, out_sign: *mut u8) -> i32;

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

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.resize(self.get_sign_len(), 0);

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
