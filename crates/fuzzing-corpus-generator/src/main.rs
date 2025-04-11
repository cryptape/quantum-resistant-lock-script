use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

#[derive(Deserialize)]
pub struct Meta {
    pub filename: String,
    pub offset: u32,
    pub length: u32,
}

#[derive(Deserialize)]
pub struct Locator {
    pub offset: u32,
    pub length: u32,
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Metadata file from merging tool
    #[arg(long)]
    metadata_file: String,

    /// Directory for dumps
    #[arg(long)]
    dumps: String,

    /// Output directory for corpuses
    #[arg(long)]
    output: String,

    /// Tracer binary
    #[arg(long, default_value = "ckb-vm-syscall-tracer")]
    tracer: String,
}

fn main() {
    let cli = Cli::parse();

    let metadata: HashMap<(u32, u32), String> = {
        let json = std::fs::read(&cli.metadata_file).expect("read metadata");
        let metas: Vec<Meta> = serde_json::from_slice(&json).expect("parse metadata");

        metas
            .into_iter()
            .map(|meta| ((meta.offset, meta.length), meta.filename))
            .collect()
    };

    for dump in run_globs(&cli.dumps, "*.json") {
        let dump_base_name = Path::new(&dump)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .strip_suffix(".json")
            .unwrap()
            .to_string();

        let tmp_dir = Path::new(&cli.output).join("tmp");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).expect("mkdir -p");

        let mut tracer_command = Command::new(&cli.tracer);
        tracer_command
            .arg("-t")
            .arg(&dump)
            .arg("-o")
            .arg(&tmp_dir)
            .arg("--cell-index")
            .arg("0");
        run_command(tracer_command);

        let locators: HashMap<String, Locator> = {
            let json = std::fs::read(&tmp_dir.join("locators.json")).expect("read locator");
            serde_json::from_slice(&json).expect("parse locators")
        };

        for trace in run_globs(tmp_dir.to_str().unwrap(), "*.traces") {
            let base_name = Path::new(&trace)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .strip_suffix(".traces")
                .unwrap()
                .to_string();
            if let Some(locator) = locators.get(&base_name) {
                let path = if locator.offset == 0 {
                    // root
                    Some(Path::new(&cli.output).join("root"))
                } else if let Some(child) = metadata.get(&(locator.offset, locator.length)) {
                    Some(Path::new(&cli.output).join(child))
                } else {
                    None
                };

                if let Some(path) = path {
                    std::fs::create_dir_all(&path).expect("mkdir -p");
                    std::fs::copy(&trace, path.join(format!("{}.data", dump_base_name)))
                        .expect("copy file");
                }
            }
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}

fn run_command(mut c: Command) {
    println!("Running Command[{:?}]", c);

    let output = c.output().unwrap_or_else(|e| {
        panic!("Error running Command[{:?}], error: {:?}", c, e);
    });

    if !output.status.success() {
        use std::io::{self, Write};
        io::stdout()
            .write_all(&output.stdout)
            .expect("stdout write");
        io::stderr()
            .write_all(&output.stderr)
            .expect("stderr write");

        panic!(
            "Command[{:?}] exits with non-success status: {:?}",
            c, output.status
        );
    }
}

fn run_globs(dir: &str, pattern: &str) -> Vec<String> {
    let mut names: Vec<String> = glob::glob(Path::new(dir).join(pattern).to_str().expect("to_str"))
        .expect("glob")
        .map(|r| r.expect("glob item").to_str().expect("to_str").to_string())
        .collect();
    names.sort();

    names
}
