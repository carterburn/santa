use anyhow::{anyhow, Result};
use std::{
    fs,
    io::{self, Read},
};
use ureq::http::StatusCode;

use clap::Parser;
use env_logger::Env;
use santa::{cli::Cli, elf::ElfFile, executor::exec};

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Cli::parse();

    let (path, bytes) = if args.fetch {
        log::debug!("Downloading from {}", args.binary);
        if !args.binary.starts_with("http://") && !args.binary.starts_with("https://") {
            return Err(anyhow!("Only http/https URIs allowed"));
        }
        let response = ureq::get(&args.binary).call()?;
        let (parts, body) = response.into_parts();
        if !matches!(parts.status, StatusCode::OK) {
            return Err(anyhow!(
                "Error retrieving binary. HTTP status: {}",
                parts.status
            ));
        }
        let mut bytes = Vec::new();
        body.into_reader().read_to_end(&mut bytes)?;
        (
            args.binary
                .split("/")
                .last()
                .ok_or(anyhow!("No binary provided"))?,
            bytes,
        )
    } else {
        match args.binary.as_str() {
            "-" => {
                log::debug!("Reading from stdin");
                let mut buffer = Vec::new();
                io::stdin().read_to_end(&mut buffer)?;
                ("stdin", buffer)
            }
            path => {
                log::debug!("Reading from file {path}");
                (path, fs::read(path)?)
            }
        }
    };

    exec(&bytes, &args.args)?;

    /*
    let elf = ElfFile::new(&bytes)?;
    let mut executor = ElfExecutor::new(elf, path.to_string())?;
    log::debug!("Args: {:?}", args.args);
    executor.execute(
        &args.args,
        args.show_stack,
        args.show_jumpbuf,
        args.jump_delay,
    )?;
    */

    Ok(())
}
