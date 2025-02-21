use clap::{Parser, Subcommand, ValueEnum};
use goblin::elf::Elf;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Symbol prefix
    #[arg(long, default_value = "")]
    prefix: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Language {
    /// Rust source file
    Rust,

    /// C source file
    C,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate symbol definition source to be used in root script
    Generate {
        /// Directory containing all leaves
        #[arg(long)]
        leaves: String,

        /// Output
        #[arg(long)]
        output: String,

        /// Language to generate for
        #[arg(long, value_enum, default_value_t = Language::C)]
        language: Language,
    },

    /// Merge multiple scripts into one, patch root script as needed
    Merge {
        /// Root script with debug symbols
        #[arg(long)]
        root_debug: String,

        /// Actual root script to patch
        #[arg(long)]
        root_actual: String,

        /// Directory containing all leaves
        #[arg(long)]
        leaves: String,

        /// Output
        #[arg(long)]
        output: String,

        /// Merge leaf binaries into root
        #[arg(long, default_value_t = true)]
        merge: bool,
    },
}

const SYMBOL_COMMON_PART: &str = "_BINARY_";

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            leaves,
            output,
            language: Language::C,
        } => {
            // For C, a header file will be generated, a macro will
            // control the presence of actual definition.
            let mut file = fs::File::create(&output).expect("create file");
            writeln!(&mut file, "#include <stdint.h>\n").expect("write");

            let leaf_names = fetch_leaf_names(&leaves);
            // Build extern lines first
            for leaf_name in &leaf_names {
                writeln!(
                    &mut file,
                    "extern const uint32_t {};",
                    offset_sname(&leaf_name, &cli.prefix)
                )
                .expect("write");
                writeln!(
                    &mut file,
                    "extern const uint32_t {};",
                    length_sname(&leaf_name, &cli.prefix)
                )
                .expect("write");
            }
            writeln!(&mut file, "").expect("write");

            // Build actual definitions, but under a ifdef guard
            writeln!(&mut file, "#ifdef CKB_SCRIPT_MERGE_TOOL_DEFINE_VARS").expect("write");
            for leaf_name in &leaf_names {
                writeln!(
                    &mut file,
                    "__attribute__ ((visibility (\"default\"))) const uint32_t {} = 0xFFFFFFFF;",
                    offset_sname(&leaf_name, &cli.prefix)
                )
                .expect("write");
                writeln!(
                    &mut file,
                    "__attribute__ ((visibility (\"default\"))) const uint32_t {} = 1;",
                    length_sname(&leaf_name, &cli.prefix)
                )
                .expect("write");
            }
            writeln!(&mut file, "#endif").expect("write");
        }
        Commands::Generate {
            leaves,
            output,
            language: Language::Rust,
        } => {
            let mut file = fs::File::create(&output).expect("create file");
            for leaf_name in fetch_leaf_names(&leaves) {
                writeln!(&mut file, "#[no_mangle]").expect("write");
                writeln!(
                    &mut file,
                    "pub static {}: u32 = 0xFFFFFFFF;",
                    offset_sname(&leaf_name, &cli.prefix)
                )
                .expect("write");
                writeln!(&mut file, "#[no_mangle]").expect("write");
                writeln!(
                    &mut file,
                    "pub static {}: u32 = 1;",
                    length_sname(&leaf_name, &cli.prefix)
                )
                .expect("write");
                writeln!(&mut file, "").expect("write");
            }
        }
        Commands::Merge {
            root_debug,
            root_actual,
            leaves,
            output,
            merge,
        } => {
            let root_debug_binary = fs::read(&root_debug).expect("read debug binary");
            let object = Elf::parse(&root_debug_binary).expect("parse elf");

            let symbols: HashMap<String, u64> = object
                .syms
                .iter()
                .filter_map(|sym| {
                    if let Some(name) = object.strtab.get_at(sym.st_name) {
                        if name.contains(SYMBOL_COMMON_PART) {
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

            let mut root_binary = fs::read(&root_actual).expect("read actual binary");
            let mut offset = root_binary.len();

            for leaf_name in fetch_leaf_names(&leaves) {
                let leaf_binary = fs::read(&leaf_name).expect("read leaf binary");
                let leaf_size = leaf_binary.len();

                let offset_symbol_name = offset_sname(&leaf_name, &cli.prefix);
                let length_symbol_name = length_sname(&leaf_name, &cli.prefix);

                let offset_symbol_offset =
                    offset_symbols.get(&offset_symbol_name).map(|v| *v as usize);
                if let Some(offset_symbol_offset) = offset_symbol_offset {
                    root_binary[offset_symbol_offset..offset_symbol_offset + 4]
                        .copy_from_slice(&p(offset));
                } else {
                    println!("Symbol {} for leaf {} does not exist in root binary, maybe it is not used?", offset_symbol_name, leaf_name);
                }

                let length_symbol_offset =
                    offset_symbols.get(&length_symbol_name).map(|v| *v as usize);
                if let Some(length_symbol_offset) = length_symbol_offset {
                    root_binary[length_symbol_offset..length_symbol_offset + 4]
                        .copy_from_slice(&p(leaf_size));
                } else {
                    println!("Symbol {} for leaf {} does not exist in root binary, maybe it is not used?", length_symbol_name, leaf_name);
                }

                if offset_symbol_offset.is_none() && length_symbol_offset.is_none() {
                    println!("Both symbols are missing for leaf {}, we are not merging this leaf script into the final script!", leaf_name);
                } else {
                    offset += leaf_size;

                    if merge {
                        root_binary.extend_from_slice(&leaf_binary);
                    }
                }
            }

            fs::write(&output, &root_binary).expect("write final binary");
        }
    }
}

fn p(v: usize) -> [u8; 4] {
    let v: u32 = v.try_into().expect("u32 overflow!");
    v.to_le_bytes()
}

fn offset_sname(leaf_path: &str, prefix: &str) -> String {
    let leaf_name = Path::new(leaf_path)
        .file_name()
        .expect("extract file name")
        .to_str()
        .expect("to str");
    format!("{}{}{}OFFSET", prefix, leaf_name, SYMBOL_COMMON_PART)
        .replace("-", "_")
        .to_uppercase()
}

fn length_sname(leaf_path: &str, prefix: &str) -> String {
    let leaf_name = Path::new(leaf_path)
        .file_name()
        .expect("extract file name")
        .to_str()
        .expect("to str");
    format!("{}{}{}LENGTH", prefix, leaf_name, SYMBOL_COMMON_PART)
        .replace("-", "_")
        .to_uppercase()
}

fn fetch_leaf_names(leaves: &str) -> Vec<String> {
    let mut leaf_names: Vec<String> =
        glob::glob(Path::new(leaves).join("*").to_str().expect("to_str"))
            .expect("glob")
            .map(|r| r.expect("glob item").to_str().expect("to_str").to_string())
            .collect();
    leaf_names.sort();

    leaf_names
}
