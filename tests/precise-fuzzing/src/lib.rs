use ckb_fips205_utils::message::{HashAlgorithm, build_fips205_final_message};
use ckb_sphincs_utils::sphincsplus::{
    sphincs_plus_get_pk_size, sphincs_plus_get_sign_size, sphincs_plus_verify,
};
use fips205::traits::{SerDes, Verifier};

pub fn run(data: &[u8]) {
    assert_eq!(sphincsplus_run(data), fips205_run(data));
}

pub fn sphincsplus_run(data: &[u8]) -> bool {
    let pk_size = unsafe { sphincs_plus_get_pk_size() } as usize;
    let sign_size = unsafe { sphincs_plus_get_sign_size() } as usize;

    if data.len() < pk_size + sign_size {
        return false;
    }

    let pk = &data[0..pk_size];
    let sign = &data[pk_size..pk_size + sign_size];
    let message = &data[pk_size + sign_size..];

    let final_mesasge = build_fips205_final_message(HashAlgorithm::None, message, Some(&[]));

    unsafe {
        sphincs_plus_verify(
            sign.as_ptr(),
            sign_size as u32,
            final_mesasge.as_ptr(),
            final_mesasge.len() as u32,
            pk.as_ptr(),
            pk_size as u32,
        ) == 0
    }
}

#[cfg(feature = "sha2_128f")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_128f::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "sha2_128s")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_128s::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "sha2_192f")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_192f::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "sha2_192s")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_192s::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "sha2_256f")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_256f::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "sha2_256s")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_256s::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "shake_128f")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_shake_128f::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "shake_128s")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_shake_128s::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "shake_192f")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_shake_192f::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "shake_192s")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_shake_192s::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "shake_256f")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_shake_256f::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

#[cfg(feature = "shake_256s")]
pub fn fips205_run(data: &[u8]) -> bool {
    use fips205::slh_dsa_shake_256s::{PK_LEN, PublicKey, SIG_LEN};
    fips205_run_inner::<PublicKey>(PK_LEN, SIG_LEN, data)
}

fn fips205_run_inner<P>(pk_len: usize, sig_len: usize, data: &[u8]) -> bool
where
    P: SerDes + Verifier,
    <P as SerDes>::ByteArray: for<'a> TryFrom<&'a [u8]>,
    for<'a> <<P as SerDes>::ByteArray as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    <P as Verifier>::Signature: for<'a> TryFrom<&'a [u8]>,
    for<'a> <<P as Verifier>::Signature as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    if data.len() < pk_len + sig_len {
        return false;
    }

    let Ok(pk) = P::try_from_bytes(&data[0..pk_len].try_into().unwrap()) else {
        return false;
    };
    let sig: <P as Verifier>::Signature = data[pk_len..pk_len + sig_len].try_into().unwrap();
    let message = &data[pk_len + sig_len..];

    pk.verify(message, &sig, &[])
}
