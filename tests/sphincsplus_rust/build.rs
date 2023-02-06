use std::path::PathBuf;

fn main() {
    let source_list = vec![
        "address.c",
        "merkle.c",
        "wots.c",
        "wotsx1.c",
        "utils.c",
        "utilsx1.c",
        "fors.c",
        "sign.c",
        "randombytes.c",

        "fips202.c",
        "hash_shake.c",
        "thash_shake_robust.c",
    ];
    let c_src_dir = PathBuf::from("../../c/ref");

    let mut builder = cc::Build::new();
    builder.define("PARAMS", "sphincs-haraka-256s");
    builder.include(&c_src_dir);

    for source in source_list {
        builder.file(c_src_dir.join(source));
    }
    builder.compile("sphincsplus");
}
