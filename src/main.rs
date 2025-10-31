use anyhow::{anyhow, Result};
use std::{
    fs,
    io::{self, Read},
};

use env_logger::Env;
use santa::{
    elf::ElfFile,
    exec::{self},
};

fn parse_args() -> (String, Vec<String>) {
    let mut args = std::env::args();
    // binary path skip over
    let _ = args.next();
    let Some(path) = args.next() else {
        panic!("Error: provide binary to load");
    };
    (path, args.collect())
}

#[cfg(feature = "web_request")]
fn retrieve_binary_from_web(binary: &str) -> Result<(&str, Vec<u8>)> {
    use ureq::http::StatusCode;
    log::debug!("Downloading from {}", binary);
    let response = ureq::get(binary).call()?;
    let (parts, body) = response.into_parts();
    if !matches!(parts.status, StatusCode::OK) {
        return Err(anyhow!(
            "Error retrieving binary. HTTP status: {}",
            parts.status
        ));
    }
    let mut bytes = Vec::new();
    body.into_reader().read_to_end(&mut bytes)?;
    Ok((
        binary
            .split("/")
            .last()
            .ok_or(anyhow!("No binary provided"))?,
        bytes,
    ))
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let (binary, args) = parse_args();

    let (path, bytes) = if binary.starts_with("http") {
        #[cfg(feature = "web_request")]
        {
            retrieve_binary_from_web(&binary)?
        }
        #[cfg(not(feature = "web_request"))]
        {
            return Err(anyhow!("Cannot make web requests"));
        }
    } else {
        match binary.as_str() {
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

    let elf = ElfFile::new(&bytes)?;
    exec::exec(&elf, &args, path)?;

    Ok(())
}
