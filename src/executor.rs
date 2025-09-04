use anyhow::{anyhow, Result};

use crate::stack::Stack;

pub fn exec(elf_bytes: &[u8], args: &[String]) -> Result<()> {
    let (binary_addr, binary_hdr, interp) = crate::loader::load(elf_bytes)?;

    Ok(())
}
