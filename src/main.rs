use anyhow::{anyhow, Result};
use std::{
    fs,
    io::{self, Read},
};

use clap::Parser;
use env_logger::Env;
use santa::{cli::Cli, elf::ElfFile, executor::ElfExecutor};

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Cli::parse();

    let bytes = if args.fetch {
        log::debug!("Downloading from {}", args.binary);
        if !args.binary.starts_with("http://") && !args.binary.starts_with("https://") {
            return Err(anyhow!("Only http/https URIs allowed"));
        }
        vec![]
    } else {
        match args.binary.as_str() {
            "-" => {
                log::debug!("Reading from stdin");
                let mut buffer = Vec::new();
                io::stdin().read_to_end(&mut buffer)?;
                buffer
            }
            path => {
                log::debug!("Reading from file {path}");
                fs::read(path)?
            }
        }
    };
    //let bytes = fs::read("/bin/echo")?;
    //let bytes = fs::read("/bin/ls")?;
    //let bytes = fs::read("/home/carter/.fly/bin/flyctl")?;
    //let bytes = fs::read("/home/carter/work/santa/templates/non_pie")?;
    //let bytes = fs::read("/home/carter/work/lighthouse/target/debug/lighthouse-agent")?;

    let elf = ElfFile::new(&bytes)?;
    let mut executor = ElfExecutor::new(elf, "/bin/echo".to_string())?;
    //let args = vec!["hello".to_string()];
    //let args = vec!["/".to_string()];
    let args = vec![];
    executor.execute(&args)?;

    Ok(())
}
