use crate::{types::TestSuite, Loader};
use ckb_fips205_utils::{construct_flag, message::build_fips205_final_message, ParamId};
use ckb_testtool::{
    ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*},
    context::Context,
};
use std::fs::File;

#[test]
fn test_nist_suite_with_c() {
    let single_run_tc_id: Option<usize> = match std::env::var("SINGLE_RUN_TC_ID") {
        Ok(val) => str::parse(&val).ok(),
        Err(_) => None,
    };

    let suite: TestSuite = {
        let f = File::open("test_vectors/internalProjection.json").expect("open file");
        serde_json::from_reader(f).expect("parse json")
    };

    for group in suite.test_groups {
        for case in group.tests {
            if let Some(single_run_tc_id) = single_run_tc_id {
                if case.tc_id != single_run_tc_id {
                    continue;
                }
            }

            let final_message = build_fips205_final_message(
                case.hash_alg,
                &case.message.0,
                case.context.as_ref().map(|hex| hex.0.as_ref()),
            );

            _run_nist_vector(
                case.tc_id,
                group.parameter_set,
                case.test_passed,
                &case.pk.0,
                &case.signature.0,
                final_message,
            );
        }
    }
}

fn _run_nist_vector(
    tc_id: usize,
    param_id: ParamId,
    test_passed: bool,
    public_key: &[u8],
    signature: &[u8],
    final_message: Vec<u8>,
) {
    let mut second_witness_data = vec![0u8; 1 + public_key.len() + signature.len()];
    second_witness_data[0] = construct_flag(param_id, true);
    second_witness_data[1..1 + public_key.len()].copy_from_slice(public_key);
    second_witness_data[1 + public_key.len()..].copy_from_slice(signature);

    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("nist-vector-tester");

    let out_point = context.deploy_cell(contract_bin);

    let lock_script = context
        .build_script(&out_point, Default::default())
        .expect("script");

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witness(Bytes::from(final_message).pack())
        .witness(Bytes::from(second_witness_data).pack())
        .build();

    let tx = context.complete_tx(tx);

    let run_result = context.verify_tx(&tx, 200_000_000);
    match run_result {
        Ok(_cycles) => {
            assert!(
                test_passed,
                "Tc ID: {} should fail but passed in CKB-VM",
                tc_id
            );
        }
        Err(e) => {
            assert!(!format!("{}", e).contains("ExceededMaximumCycles"));
            assert!(
                !test_passed,
                "Tc ID: {} should pass but failed in CKB-VM, error: {:?}",
                tc_id, e,
            );
        }
    }
}
