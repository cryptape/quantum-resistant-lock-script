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
fn get_hash_name() -> &'static str {
    "haraka"
}

#[cfg(feature = "sha2")]
fn get_hash_name() -> &'static str {
    "sha2"
}

#[cfg(feature = "shake")]
fn get_hash_name() -> &'static str {
    "shake"
}

#[cfg(feature = "thashes_robust")]
fn get_thash() -> &'static str {
    "robust"
}
#[cfg(feature = "thashes_simple")]
fn get_thash() -> &'static str {
    "simple"
}

pub fn get_hash() -> String {
    format!(
        "{}{}{}-{}",
        get_hash_name(),
        get_hash_size(),
        get_hash_option(),
        get_thash()
    )
}

#[inline(always)]
fn char_to_u8(c: char) -> u8 {
    if c.is_ascii_digit() {
        (c as u8) - b'0'
    } else if ('a'..='f').contains(&c) {
        ((c as u8) - b'a') + 0xA
    } else if ('A'..='F').contains(&c) {
        ((c as u8) - b'A') + 0xA
    } else {
        panic!("unknow char: {}", c);
    }
}

pub fn str_to_bytes(input: &str) -> Vec<u8> {
    let off = if input.contains("0x") { 2 } else { 0 };
    let input = input.as_bytes();
    assert!(input.len() % 2 == 0);
    let mut r = vec![0; (input.len() - off) / 2];

    for i in 0..r.len() {
        r[i] = (char_to_u8(input[i * 2 + off] as char) << 4)
            + char_to_u8(input[i * 2 + 1 + off] as char);
    }

    r
}

#[test]
fn test_str_to_bytes() {
    let base: [u8; 20] = [
        0x36, 0xd8, 0x07, 0x11, 0x91, 0xf8, 0x18, 0x2a, 0xe3, 0x9e, 0x67, 0xd6, 0xed, 0x5b, 0x94,
        0xbd, 0xdc, 0x5b, 0xff, 0xb6,
    ];
    let base_ = base.as_slice();

    let str_1 = "36d8071191f8182ae39e67d6ed5b94bddc5bffb6";
    let ret_1 = str_to_bytes(str_1);
    assert!(base_.cmp(ret_1.as_slice()).is_eq());

    let str_2 = "0x36d8071191f8182ae39e67d6ed5b94bddc5bffb6";
    let ret_2 = str_to_bytes(str_2);
    assert!(base_.cmp(ret_2.as_slice()).is_eq());
}
