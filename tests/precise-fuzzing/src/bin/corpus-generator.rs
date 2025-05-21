use clap::Parser;
use fips205::traits::{SerDes, Signer};
use precise_fuzzing::{fips205_run, sphincsplus_run};
use rand::{CryptoRng, Rng, SeedableRng, rngs::StdRng};
use std::path::Path;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Output directory for corpuses
    #[arg(long)]
    output: String,
}

fn main() {
    let cli = Cli::parse();
    let output_dir = Path::new(&cli.output);
    std::fs::create_dir_all(output_dir).expect("mkdir -p");

    let seed: u64 = match std::env::var("SEED") {
        Ok(val) => str::parse(&val).expect("parsing number"),
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };
    println!("Seed: {}", seed);

    let mut rng = StdRng::seed_from_u64(seed);

    for i in 0..50 {
        let message = {
            let len = rng.gen_range(1..1000);
            let mut data = vec![0u8; len];
            rng.fill(&mut data[..]);
            data
        };

        let corpus = sign(&message, &mut rng);
        assert!(fips205_run(&corpus));
        assert!(sphincsplus_run(&corpus));

        let valid_path = output_dir.join(format!("valid_{}", i));
        std::fs::write(valid_path, &corpus).expect("write");

        for j in 0..3 {
            let mut invalid_corpus = corpus.clone();
            let invalid_corpus_len = invalid_corpus.len();
            invalid_corpus[rng.gen_range(0..invalid_corpus_len)] ^= 1 << rng.gen_range(0..8);

            assert!(!fips205_run(&invalid_corpus));
            assert!(!sphincsplus_run(&invalid_corpus));

            let invalid_path = output_dir.join(format!("invalid_{}", i * 3 + j));
            std::fs::write(invalid_path, invalid_corpus).expect("write");
        }
    }
}

#[cfg(feature = "sha2_128f")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_sha2_128f::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "sha2_128s")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_sha2_128s::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "sha2_192f")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_sha2_192f::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "sha2_192s")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_sha2_192s::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "sha2_256f")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_sha2_256f::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "sha2_256s")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_sha2_256s::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "shake_128f")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_shake_128f::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "shake_128s")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_shake_128s::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "shake_192f")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_shake_192f::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "shake_192s")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_shake_192s::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "shake_256f")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_shake_256f::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

#[cfg(feature = "shake_256s")]
fn sign<R: Rng + CryptoRng>(message: &[u8], rng: &mut R) -> Vec<u8> {
    use fips205::slh_dsa_shake_256s::try_keygen_with_rng;
    let sk = try_keygen_with_rng(rng).expect("generate secret key").1;
    sign_inner(sk, message, rng)
}

fn sign_inner<S, R>(sk: S, message: &[u8], rng: &mut R) -> Vec<u8>
where
    S: SerDes + Signer,
    R: Rng + CryptoRng,
    <S as Signer>::Signature: IntoIterator<Item = u8>,
    <S as Signer>::PublicKey: SerDes,
    <<S as Signer>::PublicKey as SerDes>::ByteArray: IntoIterator<Item = u8>,
{
    let sig = sk
        .try_sign_with_rng(rng, message, &[], false)
        .expect("sign");

    let pk_bytes = sk.get_public_key().into_bytes();

    let mut result = vec![];
    result.extend(pk_bytes);
    result.extend(sig);
    result.extend_from_slice(message);

    result
}
