use ckb_gen_types::{
    bytes::Bytes,
    packed::{CellOutput, Script, Transaction, WitnessArgsReader},
    prelude::*,
};
use ckb_mock_tx_types::MockTransaction;
use molecule::error::VerificationError;
use std::io;

#[derive(Debug)]
#[allow(dead_code)]
pub enum CkbTxMessageAllError {
    InvalidMockTx,
    UnknownScriptGroup,
    Witness(VerificationError),
    Io(io::Error),
}

impl From<VerificationError> for CkbTxMessageAllError {
    fn from(e: VerificationError) -> Self {
        CkbTxMessageAllError::Witness(e)
    }
}

impl From<io::Error> for CkbTxMessageAllError {
    fn from(e: io::Error) -> Self {
        CkbTxMessageAllError::Io(e)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ScriptOrIndex {
    Script(Script),
    Index(usize),
}

pub fn generate_ckb_tx_message_all_from_mock_tx<W: io::Write>(
    mock_tx: &MockTransaction,
    script_or_index: ScriptOrIndex,
    writer: &mut W,
) -> Result<(), CkbTxMessageAllError> {
    let inputs = locate_inputs(mock_tx)?;
    generate_ckb_tx_message_all(&mock_tx.tx, &inputs, script_or_index, writer)
}

pub fn generate_ckb_tx_message_all<W: io::Write>(
    tx: &Transaction,
    inputs: &[(CellOutput, Bytes)],
    script_or_index: ScriptOrIndex,
    writer: &mut W,
) -> Result<(), CkbTxMessageAllError> {
    assert_eq!(tx.raw().inputs().len(), inputs.len());
    let script_group_indices = find_script_group(inputs, script_or_index)?;

    // Ensure the first witness of current script group is a WitnessArgs
    let first_witness_content = tx
        .witnesses()
        .get(script_group_indices[0])
        .ok_or(CkbTxMessageAllError::InvalidMockTx)?
        .raw_data();
    let first_witness = WitnessArgsReader::from_slice(&first_witness_content)?;

    // Hash tx hash
    writer.write_all(tx.calc_tx_hash().as_slice())?;

    // Hash contents of all input cells
    for (cell_output, data) in inputs {
        writer.write_all(cell_output.as_slice())?;

        write_length(data.len(), writer)?;
        writer.write_all(data)?;
    }

    // Hash the first witness of current script group
    write_length(first_witness.input_type().as_slice().len(), writer)?;
    writer.write_all(first_witness.input_type().as_slice())?;
    write_length(first_witness.output_type().as_slice().len(), writer)?;
    writer.write_all(first_witness.output_type().as_slice())?;

    // Hash the remaining witnesses in current script group
    for i in script_group_indices.iter().skip(1) {
        if let Some(witness) = tx.witnesses().get(*i).map(|w| w.raw_data()) {
            write_length(witness.len(), writer)?;
            writer.write_all(&witness)?;
        }
    }

    // Hash witnesses that do not have input cells of the same indices
    for witness in tx
        .witnesses()
        .into_iter()
        .skip(tx.raw().inputs().len())
        .map(|w| w.raw_data())
    {
        write_length(witness.len(), writer)?;
        writer.write_all(&witness)?;
    }

    writer.flush()?;
    Ok(())
}

fn locate_inputs(
    mock_tx: &MockTransaction,
) -> Result<Vec<(CellOutput, Bytes)>, CkbTxMessageAllError> {
    let mut result = Vec::with_capacity(mock_tx.tx.raw().inputs().len());
    for input in mock_tx.tx.raw().inputs() {
        let mock_input = mock_tx
            .mock_info
            .inputs
            .iter()
            .find(|mock_input| mock_input.input == input)
            .ok_or(CkbTxMessageAllError::InvalidMockTx)?;
        result.push((mock_input.output.clone(), mock_input.data.clone()));
    }
    Ok(result)
}

fn find_script_group(
    inputs: &[(CellOutput, Bytes)],
    script_or_index: ScriptOrIndex,
) -> Result<Vec<usize>, CkbTxMessageAllError> {
    let script = match script_or_index {
        ScriptOrIndex::Script(script) => script,
        ScriptOrIndex::Index(i) => inputs
            .get(i)
            .ok_or(CkbTxMessageAllError::UnknownScriptGroup)?
            .0
            .lock(),
    };
    let indices: Vec<_> = inputs
        .iter()
        .enumerate()
        .filter(|(_i, (cell_output, _data))| cell_output.lock() == script)
        .map(|(i, _)| i)
        .collect();
    if indices.is_empty() {
        return Err(CkbTxMessageAllError::UnknownScriptGroup);
    }
    Ok(indices)
}

#[inline]
fn write_length<W>(length: usize, writer: &mut W) -> Result<(), CkbTxMessageAllError>
where
    W: io::Write,
{
    let length: u32 = length.try_into().expect("convert to u32");
    writer.write_all(&length.to_le_bytes())?;
    Ok(())
}
