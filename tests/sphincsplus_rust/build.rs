use std::path::PathBuf;

fn main() {
    let source_list = vec![
        "ref/params.c",
        "ref/address.c",
        "ref/merkle.c",
        "ref/wots.c",
        "ref/wotsx1.c",
        "ref/utils.c",
        "ref/utilsx1.c",
        "ref/fors.c",
        "ref/sign.c",
        "ref/randombytes.c",
        "ckb-sphincsplus.c",
        // shake
        "ref/fips202.c",
        "ref/hash_shake.c",
        "ref/thash_shake_robust.c",
        "ref/thash_shake_simple.c",
        // sha2
        "ref/sha2.c",
        "ref/hash_sha2.c",
        "ref/thash_sha2_robust.c",
        "ref/thash_sha2_simple.c",
        // haraka
        "ref/haraka.c",
        "ref/hash_haraka.c",
        "ref/thash_haraka_robust.c",
        "ref/thash_haraka_simple.c",
    ];

    let c_src_dir = PathBuf::from("../../c/");

    let mut builder = cc::Build::new();
    builder.include(&c_src_dir);
    builder.include(&c_src_dir.join("ref"));

    for source in source_list {
        builder.file(c_src_dir.join(source));
    }
    builder.compile("sphincsplus");
}
