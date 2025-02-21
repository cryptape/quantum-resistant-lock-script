use clap::Parser;
use goblin::elf::Elf;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Root binary with debug symbols
    #[arg(long)]
    root_debug_binary: String,

    /// Actual root binary to patch
    #[arg(long)]
    root_actual_binary: String,

    /// Template for leaf binaries, use '@@' to denote params name
    #[arg(long)]
    leaf_binary_template: String,

    /// Output
    #[arg(long)]
    output_binary: String,

    /// Params definition file
    #[arg(long)]
    params_file: String,

    /// Merge leaf binaries into root
    #[arg(long)]
    merge: bool,
}

fn main() {
    let cli = Cli::parse();

    let root_debug_binary = fs::read(&cli.root_debug_binary).expect("read debug binary");
    let object = Elf::parse(&root_debug_binary).expect("parse elf");

    let symbols: HashMap<String, u64> = object
        .syms
        .iter()
        .filter_map(|sym| {
            if let Some(name) = object.strtab.get_at(sym.st_name) {
                if name.contains("_binary_") {
                    return Some((name.to_string(), sym.st_value));
                }
            }
            None
        })
        .collect();

    let offset_symbols: HashMap<String, u64> = symbols
        .into_iter()
        .filter_map(|(name, address)| {
            if let Some(h) = object
                .program_headers
                .iter()
                .find(|h| address >= h.p_vaddr && address + 4 <= h.p_vaddr + h.p_filesz)
            {
                return Some((name, address - h.p_vaddr + h.p_offset));
            }
            None
        })
        .collect();

    let mut root_binary = fs::read(&cli.root_actual_binary).expect("read actual binary");
    let mut offset = root_binary.len();

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

    for (params_id, params_name) in params {
        let leaf_binary_name = cli.leaf_binary_template.replace("@@", &params_name);
        let leaf_binary = fs::read(&leaf_binary_name).expect("read leaf binary");
        let leaf_size = leaf_binary.len();

        let offset_symbol_name = format!("param{}_binary_offset", params_id);
        let length_symbol_name = format!("param{}_binary_length", params_id);

        let offset_symbol_offset = *offset_symbols
            .get(&offset_symbol_name)
            .expect("fetch offset symbol offset") as usize;
        let length_symbol_offset = *offset_symbols
            .get(&length_symbol_name)
            .expect("fetch length symbol offset") as usize;

        root_binary[offset_symbol_offset..offset_symbol_offset + 4].copy_from_slice(&p(offset));
        root_binary[length_symbol_offset..length_symbol_offset + 4].copy_from_slice(&p(leaf_size));

        offset += leaf_size;

        if cli.merge {
            root_binary.extend_from_slice(&leaf_binary);
        }
    }

    fs::write(&cli.output_binary, root_binary).expect("write root binary");
}

fn p(v: usize) -> [u8; 4] {
    let v: u32 = v.try_into().expect("u32 overflow!");
    v.to_le_bytes()
}
