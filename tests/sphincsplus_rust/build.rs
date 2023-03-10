use std::path::PathBuf;

#[cfg(feature = "hash_128")]
fn get_hash_size() -> usize {
    128
}
#[cfg(feature = "hash_192")]
fn get_hash_size() -> usize {
    192
}
#[cfg(feature = "hash_256")]
fn get_hash_size() -> usize {
    256
}

#[cfg(feature = "hash_options_f")]
fn get_hash_option() -> &'static str {
    "f"
}
#[cfg(feature = "hash_options_s")]
fn get_hash_option() -> &'static str {
    "s"
}

#[cfg(feature = "haraka")]
fn get_hash_info() -> (&'static str, Vec<&'static str>) {
    #[cfg(feature = "thashes_robust")]
    let thash_file = "../deps/sphincsplus/ref/thash_haraka_robust.c";
    #[cfg(feature = "thashes_simple")]
    let thash_file = "../deps/sphincsplus/ref/thash_haraka_simple.c";

    (
        "haraka",
        vec![
            "../deps/sphincsplus/ref/haraka.c",
            "../deps/sphincsplus/ref/hash_haraka.c",
            thash_file,
        ],
    )
}
#[cfg(feature = "sha2")]
fn get_hash_info() -> (&'static str, Vec<&'static str>) {
    #[cfg(feature = "thashes_robust")]
    let thash_file = "../deps/sphincsplus/ref/thash_sha2_robust.c";
    #[cfg(feature = "thashes_simple")]
    let thash_file = "../deps/sphincsplus/ref/thash_sha2_simple.c";

    (
        "sha2",
        vec![
            "../deps/sphincsplus/ref/sha2.c",
            "../deps/sphincsplus/ref/hash_sha2.c",
            thash_file,
        ],
    )
}
#[cfg(feature = "shake")]
fn get_hash_info() -> (&'static str, Vec<&'static str>) {
    #[cfg(feature = "thashes_robust")]
    let thash_file = "../deps/sphincsplus/ref/thash_shake_robust.c";
    #[cfg(feature = "thashes_simple")]
    let thash_file = "../deps/sphincsplus/ref/thash_shake_simple.c";

    (
        "shake",
        vec![
            "../deps/sphincsplus/ref/fips202.c",
            "../deps/sphincsplus/ref/hash_shake.c",
            thash_file,
        ],
    )
}

fn main() {
    let mut source_list = vec![
        "../deps/sphincsplus/ref/address.c",
        "../deps/sphincsplus/ref/merkle.c",
        "../deps/sphincsplus/ref/wots.c",
        "../deps/sphincsplus/ref/wotsx1.c",
        "../deps/sphincsplus/ref/utils.c",
        "../deps/sphincsplus/ref/utilsx1.c",
        "../deps/sphincsplus/ref/fors.c",
        "../deps/sphincsplus/ref/sign.c",
        "../deps/sphincsplus/ref/randombytes.c",
        "ckb-sphincsplus.c",
    ];

    let (hash_name, mut hash_src_files) = get_hash_info();

    source_list.append(&mut hash_src_files);
    let define_param = format!(
        "sphincs-{}-{}{}",
        hash_name,
        get_hash_size(),
        get_hash_option()
    );

    let c_src_dir = PathBuf::from("../../c/");

    let mut builder = cc::Build::new();
    builder.define("PARAMS", define_param.as_str());
    builder.include(&c_src_dir);
    builder.include(
        &c_src_dir
            .join("..")
            .join("deps")
            .join("sphincsplus")
            .join("ref"),
    );

    for source in source_list {
        builder.file(c_src_dir.join(source));
    }
    builder.compile("sphincsplus");
}
