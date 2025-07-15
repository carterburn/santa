use std::{error::Error, fs};

use env_logger::Env;
use santa::{elf::ElfFile, executor::ElfExecutor};

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = fs::read("/bin/echo")?;

    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let elf = ElfFile::new(&bytes).map_err(|e| e.to_string())?;
    let mut executor = ElfExecutor::new(elf, "/bin/echo".to_string())?;
    let args = vec!["hello".to_string()];
    executor.execute(&args);

    std::thread::sleep(std::time::Duration::from_secs(20));

    Ok(())
}
