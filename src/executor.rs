use std::ffi::CString;

use crate::elf::{
    types::{ElfMachine, ElfType, PhdrType},
    ElfFile, ElfHeader, ProgramHeader,
};
use anyhow::{anyhow, Result};

#[derive(Debug)]
pub struct Segment<'a> {
    pub header: &'a ProgramHeader,
    pub data: &'a [u8],
}

impl<'a> Segment<'a> {
    pub fn new(header: &'a ProgramHeader, elf_bytes: &'a [u8]) -> Self {
        println!("Offset: {}; File Sz: {}", header.p_offset, header.p_filesz);
        let start = header.p_offset as usize;
        let end = header.p_offset as usize + header.p_filesz as usize;
        println!("   Range: {start}..{end}");
        let data = &elf_bytes[start..end];

        Self { header, data }
    }
}

/// Similar to the ElfFile / ELF parser, but verifies it meets the requirements for the Rust UL
/// exec before allowing creation
#[derive(Debug)]
pub struct ElfVerifier<'a> {
    pub e_hdr: &'a ElfHeader,
    pub pie: bool,
    pub interp: Option<CString>,
    pub segments: Vec<Segment<'a>>,
}

impl<'a> ElfVerifier<'a> {
    pub fn parse(elf_bytes: &'a [u8], file: &'a ElfFile) -> Result<Self> {
        if !matches!(file.header.e_type, ElfType::Executable | ElfType::Shared) {
            return Err(anyhow!("ELF is not an executable or shared object file"));
        }

        if file.program_headers.is_empty() {
            return Err(anyhow!("No program headers found in ELF"));
        }

        if !matches!(
            file.header.e_machine,
            ElfMachine::X86 | ElfMachine::X86_64 | ElfMachine::AArch64
        ) {
            return Err(anyhow!("ELF machinei not is not supported"));
        }

        // filter to only get PT_LOAD and PT_INTERP program headers
        let ph_entries: Vec<&ProgramHeader> = file
            .program_headers
            .iter()
            .filter(|ph| matches!(ph.p_type, PhdrType::Load | PhdrType::Interp))
            .collect();

        // check if any of the PT_LOAD headers have a virtual address of 0x00 (if they do, we have
        // a PIE binary, otherwise it's not PIE)
        let pie = ph_entries.iter().find(|ph| ph.p_vaddr == 0x00).is_some();

        let mut segments = vec![];

        // check alignment on all the LOAD headers
        for e in ph_entries
            .iter()
            .filter(|ph| matches!(ph.p_type, PhdrType::Load))
        {
            // check alignment then add the segment
            if e.p_align != 0x00 && e.p_align != 0x01 {
                if e.p_vaddr % e.p_align != e.p_offset % e.p_align {
                    return Err(anyhow!("p_vaddr should equal p_offset modulo p_align"));
                }
            } else {
                return Err(anyhow!(
                    "Non-alignment specified by p_align is not supported"
                ));
            }

            segments.push(Segment::new(e, elf_bytes));
        }

        // check interpreter presence
        let interp = ph_entries
            .iter()
            .find(|ph| matches!(ph.p_type, PhdrType::Interp))
            .and_then(|entry| {
                let start = entry.p_offset as usize;
                CString::from_vec_with_nul(
                    elf_bytes[start..start + entry.p_filesz as usize].to_vec(),
                )
                .ok()
            });

        Ok(Self {
            e_hdr: &file.header,
            pie,
            interp,
            segments,
        })

        //
        // do we want to read the data as well? i think no at this moment because I like the ref to
        // PHeaders, but we could also create a new type like Segment that has the header and the
        // data of the segment?
    }
}
