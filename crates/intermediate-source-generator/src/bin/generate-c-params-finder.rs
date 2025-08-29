use ckb_fips205_utils::collect_param_ids;

fn main() {
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

    let mut min_nid = u8::MAX;
    for param_id in collect_param_ids() {
        let name = format!("CKB_{param_id}")
            .replace("-", "_")
            .replace("SLH_DSA", "SPHINCS")
            .to_uppercase();
        let nid: u8 = param_id.into();
        min_nid = std::cmp::min(min_nid, nid);
        println!(
            r#"  {{
    .pk_bytes = CKB_SPHINCS_PARAM{nid}_PK_BYTES,
    .sign_bytes = CKB_SPHINCS_PARAM{nid}_SIGN_BYTES,
    .offset_ptr = &{name}_BINARY_OFFSET,
    .length_ptr = &{name}_BINARY_LENGTH,
    .name = "{param_id}",
  }},"#
        );
    }

    println!(
        r#"}};
#define CKB_SPHINCS_SUPPORTED_PARAMS_COUNT (sizeof(ckb_sphincs_supported_params) / sizeof(CkbSphincsParams))
#define CKB_SPHINCS_MIN_PARAM_ID {min_nid}"#
    )
}
