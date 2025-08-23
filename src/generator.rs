use std::time::Duration;

use crate::{
    elf::{types::ElfMachine, ElfFile},
    stack::{Stack, StackOffsets},
};
use anyhow::{anyhow, Result};
use codegenx64::CodeGenX64;
use nix::libc::{MAP_ANONYMOUS, MAP_PRIVATE, PF_R, PF_W, PF_X, PROT_EXEC, PROT_READ, PROT_WRITE};

pub mod codegenx64;

pub trait CodeGenerator {
    fn mprotect(&self, addr: usize, length: usize, prot: u32);
    fn munmap(&self, addr: usize, length: usize) -> Vec<u8>;
    fn memcpy_from_offset(&self, offset: usize, src: usize, sz: usize) -> Vec<u8>;
    fn mmap(&self, addr: usize, length: usize, prot: u32, flags: u32, offset: usize) -> Vec<u8>;
    fn generate_auxv_fixup(
        &self,
        stack: &mut Stack,
        auxv_offset: usize,
        map_offset: usize,
        relative: bool,
    ) -> Vec<u8>;
    fn generate_jumpcode(
        &self,
        stack: &mut Stack,
        entry_ptr: usize,
        jump_delay: Option<Duration>,
    ) -> Vec<u8>;
}

pub struct CodeGen<'a, T: CodeGenerator> {
    file: &'a ElfFile,
    interp: Option<&'a ElfFile>,
    generator: T,
}

impl<'a, T: CodeGenerator> CodeGen<'a, T> {
    pub fn new(file: &'a ElfFile, interp: Option<&'a ElfFile>, generator: T) -> Result<Self> {
        if let Some(i_file) = interp {
            if i_file.header.e_machine != file.header.e_machine {
                Err(anyhow!("Mismatched machine type for interpreter and ELF"))?
            }
        }

        Ok(Self {
            file,
            interp,
            generator,
        })
    }

    pub fn generate(&mut self, stack: &mut Stack, jump_delay: Option<Duration>) -> Result<Vec<u8>> {
        let mut code = vec![];
        code.extend_from_slice(&self.generate_elf_loader(self.file)?);
        code.extend_from_slice(&self.generator.generate_auxv_fixup(
            stack,
            StackOffsets::OffsetAtPhdr.into(),
            self.file.header.e_phoff.try_into()?,
            true,
        ));
        code.extend_from_slice(&self.generator.generate_auxv_fixup(
            stack,
            StackOffsets::OffsetAtEntry.into(),
            self.file.header.e_entry.try_into()?,
            self.file.pie,
        ));

        let entry_point = match self.interp {
            Some(interpreter) => {
                code.extend_from_slice(&self.generate_elf_loader(interpreter)?);
                code.extend_from_slice(&self.generator.generate_auxv_fixup(
                    stack,
                    StackOffsets::OffsetAtBase.into(),
                    0,
                    true,
                ));
                interpreter.header.e_entry
            }
            None => {
                if self.file.pie {
                    self.file.header.e_entry
                } else {
                    self.file.header.e_entry
                        - self
                            .file
                            .segments
                            .first()
                            .ok_or(anyhow!("no segments in ELF"))?
                            .header
                            .p_vaddr
                }
            }
        };

        log::debug!(
            "Generating jumpcode with entry_point {entry_point:#08x?} and stack {:08x?}",
            stack.base()
        );

        code.extend_from_slice(&self.generator.generate_jumpcode(
            stack,
            entry_point.try_into()?,
            jump_delay,
        ));

        Ok(code)
    }

    fn generate_elf_loader(&mut self, file: &'a ElfFile) -> Result<Vec<u8>> {
        let mut code = vec![];
        let addr = if file.pie {
            0x00
        } else {
            file.segments
                .first()
                .ok_or(anyhow!("No valid segments"))?
                .header
                .p_vaddr
        };
        let size = file.memory_size()?;

        let protections = PROT_WRITE | PROT_EXEC | PROT_READ;
        let flags = MAP_ANONYMOUS | MAP_PRIVATE;

        // alignment
        let addr = page_floor(addr.try_into()?)?;
        let size = page_ceil(size)?;

        code.extend(self.generator.munmap(addr, size));
        code.extend(
            self.generator
                .mmap(addr, size, protections.try_into()?, flags.try_into()?, 0),
        );

        for e in &file.segments {
            let src = e.data.as_ptr().addr();
            let sz = e.header.p_filesz;
            let mut vaddr = e.header.p_vaddr;
            let flags = e.header.p_flags;

            if !file.pie {
                vaddr -= file.segments[0].header.p_vaddr;
            }
            code.extend(
                self.generator
                    .memcpy_from_offset(vaddr.try_into()?, src, sz.try_into()?),
            );

            let mut prot = if flags & PF_R != 0 { PROT_READ } else { 0 };
            prot |= if flags & PF_W != 0 { PROT_WRITE } else { 0 };
            prot |= if flags & PF_X != 0 { PROT_EXEC } else { 0 };
            _ = prot;

            // ulexecve.py didn't use this, but I'm pretty sure it is necessary...
            // code.extend(self.generator.mprotect(vaddr, page_ceil(memsz), prot))
        }

        Ok(code)
    }
}

fn page_floor(initial: usize) -> Result<usize> {
    Ok(initial & !(Stack::get_page_size()? - 1))
}

fn page_ceil(initial: usize) -> Result<usize> {
    page_floor(initial + Stack::get_page_size()? - 1)
}
