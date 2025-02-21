use clap::Parser;
use std::fs;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Params definition file
    #[arg(long)]
    params_file: String,
}

fn main() {
    let cli = Cli::parse();

    let params: Vec<(usize, String)> = fs::read_to_string(&cli.params_file)
        .expect("read params file")
        .lines()
        .map(|line| {
            let parts: Vec<&str> = line.split(" ").collect();
            (
                usize::from_str_radix(parts[0], 10).expect("parse number"),
                parts[1].to_string(),
            )
        })
        .collect();

    println!(
        r#"#include <stdint.h>
#include "aggregated-params.h"
#include "leaf-vars.h""#
    );

    println!(
        r#"
typedef struct {{
  uint32_t pk_bytes;
  uint32_t sign_bytes;
  const uint32_t *offset_ptr;
  const uint32_t *length_ptr;
  const char *name;
}} CkbSphincsParams;

CkbSphincsParams ckb_sphincs_supported_params[] = {{"#
    );

    for (params_id, params_name) in &params {
        let name = format!("CKB_{}", params_name)
            .replace("-", "_")
            .to_uppercase();
        println!(
            r#"  {{
    .pk_bytes = PARAM{params_id}_PK_BYTES,
    .sign_bytes = PARAM{params_id}_SIGN_BYTES,
    .offset_ptr = &{name}_BINARY_OFFSET,
    .length_ptr = &{name}_BINARY_LENGTH,
    .name = "{params_name}",
  }},"#
        );
    }

    println!(
        r#"}};
#define CKB_SPHINCS_SUPPORTED_PARAMS_COUNT (sizeof(ckb_sphincs_supported_params) / sizeof(CkbSphincsParams))"#
    )
}
