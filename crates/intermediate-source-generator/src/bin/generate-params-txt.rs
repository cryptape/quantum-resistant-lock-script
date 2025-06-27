use ckb_fips205_utils::collect_param_ids;

fn main() {
    for param_id in collect_param_ids() {
        let formatted_id: u8 = param_id.into();
        let formatted_name = format!("sphincs-{param_id}")
            .replace("SLH-DSA-", "")
            .to_lowercase();
        println!("{formatted_id} {formatted_name}");
    }
}
