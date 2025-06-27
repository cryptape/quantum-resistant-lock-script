use ckb_fips205_utils::collect_param_ids;

fn main() {
    println!(
        r#"
use super::offsets::*;
use super::sizes::*;
use ckb_fips205_utils::ParamId;
"#
    );

    println!(
        r#"
pub const PARAM_IDS_COUNT: usize = {};
"#,
        collect_param_ids().len(),
    );

    println!(
        r#"
pub fn lengths(param_id: ParamId) -> (usize, usize) {{
    match param_id {{
"#
    );

    let mut min_nid = u8::MAX;
    for param_id in collect_param_ids() {
        let symbol_name = {
            let name = format!("{param_id}").replace("SLH-DSA-", "");
            let parts: Vec<_> = name.split("-").collect();
            capitalize(parts[0]) + &parts[1].to_uppercase().to_string()
        };
        let nid: u8 = param_id.into();
        min_nid = std::cmp::min(nid, min_nid);
        println!(
            r#"ParamId::{symbol_name} => (
                CKB_SPHINCS_PARAM{nid}_PK_BYTES,
                CKB_SPHINCS_PARAM{nid}_SIGN_BYTES,
            ),"#
        );
    }

    println!("}} }}");

    println!(
        r#"
pub fn indices(param_id: ParamId) -> usize {{
    match param_id {{
"#
    );

    for param_id in collect_param_ids() {
        let symbol_name = {
            let name = format!("{param_id}").replace("SLH-DSA-", "");
            let parts: Vec<_> = name.split("-").collect();
            capitalize(parts[0]) + &parts[1].to_uppercase().to_string()
        };
        let nid: u8 = param_id.into();
        let index = nid - min_nid;

        println!(r#"ParamId::{symbol_name} => {index},"#);
    }

    println!("}} }}");

    println!(
        r#"
pub fn binary_infos(param_id: ParamId) -> (*const u32, *const u32) {{
    match param_id {{
"#
    );

    for param_id in collect_param_ids() {
        let name = format!("CKB_{param_id}")
            .replace("-", "_")
            .replace("SLH_DSA", "SPHINCS")
            .to_uppercase();
        let symbol_name = {
            let name = format!("{param_id}").replace("SLH-DSA-", "");
            let parts: Vec<_> = name.split("-").collect();
            capitalize(parts[0]) + &parts[1].to_uppercase().to_string()
        };
        println!(
            r#"ParamId::{symbol_name} => (
                (&{name}_BINARY_OFFSET) as *const u32,
                (&{name}_BINARY_LENGTH) as *const u32,
            ),"#
        );
    }

    println!("}} }}");
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase().to_string(),
    }
}
