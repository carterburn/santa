use std::{error::Error, fs};

use env_logger::Env;
use santa::elf::ElfFile;

fn t(v: Vec<u8>) -> bool {
    v.is_empty()
}

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = fs::read("/bin/echo")?;

    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let elf = ElfFile::new(&bytes).map_err(|e| e.to_string())?;

    Ok(())
}
