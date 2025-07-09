use std::ffi::CString;

use anyhow::{anyhow, Result};
// Word: U32
// Half: U16
// Addr: U64
// Xword: U64
// Sxword: I64
use zerocopy::{BigEndian, FromBytes, Immutable, KnownLayout, LittleEndian, U16, U32, U64};

use crate::elf::{ElfFile, ElfHeader, ProgramHeader, Segment};

use super::{ElfMachine, ElfType};

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawEHdr64Le {
    pub e_ident: [u8; 16],
    pub e_type: U16<LittleEndian>,
    pub e_machine: U16<LittleEndian>,
    pub e_version: U32<LittleEndian>,
    pub e_entry: U64<LittleEndian>,
    pub e_phoff: U64<LittleEndian>,
    pub e_shoff: U64<LittleEndian>,
    pub e_flags: U32<LittleEndian>,
    pub e_ehsize: U16<LittleEndian>,
    pub e_phentsize: U16<LittleEndian>,
    pub e_phnum: U16<LittleEndian>,
    pub e_shentsize: U16<LittleEndian>,
    pub e_shnum: U16<LittleEndian>,
    pub e_shstrndx: U16<LittleEndian>,
}

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawPHdr64Le {
    pub p_type: U32<LittleEndian>,
    pub p_flags: U32<LittleEndian>,
    pub p_offset: U64<LittleEndian>,
    pub p_vaddr: U64<LittleEndian>,
    pub p_paddr: U64<LittleEndian>,
    pub p_filesz: U64<LittleEndian>,
    pub p_memsz: U64<LittleEndian>,
    pub p_align: U64<LittleEndian>,
}

impl RawPHdr64Le {
    pub fn parse<'a>(elf_bytes: &'a [u8], header: &ElfHeader) -> Result<Vec<&'a Self>> {
        let mut p_headers = vec![];
        for hdr in 0..header.e_phnum {
            let index: usize = header.e_phoff as usize + (size_of::<Self>() * hdr as usize);
            eprintln!("First 8 bytes: {:?}", &elf_bytes[index..index + 8]);
            p_headers.push(
                Self::ref_from_bytes(&elf_bytes[index..index + size_of::<Self>()])
                    .map_err(|_| anyhow!("Unable to transmute to raw program header"))?,
            );
        }
        Ok(p_headers)
    }
}

pub fn parse_elf64(elf_bytes: &[u8]) -> Result<ElfFile> {
    let header = ElfHeader::parse_64le(
        RawEHdr64Le::ref_from_bytes(&elf_bytes[..size_of::<RawEHdr64Le>()])
            .map_err(|_| anyhow!("Error parsing raw ELF header"))?,
    );

    if !matches!(header.e_type, ElfType::Executable | ElfType::Shared) {
        return Err(anyhow!("ELF is not an executable or shared object file"));
    }

    if !matches!(header.e_machine, ElfMachine::X86_64 | ElfMachine::AArch64) {
        return Err(anyhow!("ELF machinei not is not supported"));
    }

    let mut segments = vec![];
    let mut interp = None;

    for hdr in 0..header.e_phnum {
        let index: usize = header.e_phoff as usize + (size_of::<RawPHdr64Le>() * hdr as usize);
        let p_header = ProgramHeader::parse_64le(
            RawPHdr64Le::ref_from_bytes(&elf_bytes[index..index + size_of::<RawPHdr64Le>()])
                .map_err(|_| anyhow!("Unable to transmute raw program header"))?,
        );

        match p_header.p_type {
            super::PhdrType::Load => {
                // check alignment then add the segment
                if p_header.p_align != 0x00 && p_header.p_align != 0x01 {
                    if p_header.p_vaddr % p_header.p_align != p_header.p_offset % p_header.p_align {
                        return Err(anyhow!("p_vaddr should equal p_offset modulo p_align"));
                    }
                } else {
                    return Err(anyhow!(
                        "Non-alignment specified by p_align is not supported"
                    ));
                }

                segments.push(Segment::new(p_header, elf_bytes));
            }
            super::PhdrType::Interp => {
                let start = p_header.p_offset as usize;
                let interpreter_path = CString::from_vec_with_nul(
                    elf_bytes[start..start + p_header.p_filesz as usize].to_vec(),
                )
                .map_err(|_| anyhow!("Unable to retrieve interpreter string"))?;

                log::debug!(
                    "PT_INTERP at offset 0x{:08x}: interpreter set as {:?}",
                    p_header.p_offset,
                    interpreter_path
                );

                interp = Some(interpreter_path);
            }
            _ => {
                continue;
            }
        }
    }

    if segments.is_empty() {
        return Err(anyhow!("No valid loadable segments"));
    }

    let pie = segments.iter().any(|seg| seg.header.p_vaddr == 0x00);
    log::debug!(
        "{}",
        if pie {
            "Identified as PIE executable"
        } else {
            "Identified as non-PIE executable"
        }
    );

    Ok(ElfFile {
        header,
        segments,
        pie,
        interp,
    })
}

#[derive(Debug, FromBytes)]
#[repr(C)]
pub struct RawEHdr64Be {
    pub e_ident: [u8; 16],
    pub e_type: U16<BigEndian>,
    pub e_machine: U16<BigEndian>,
    pub e_version: U32<BigEndian>,
    pub e_entry: U64<BigEndian>,
    pub e_phoff: U64<BigEndian>,
    pub e_shoff: U64<BigEndian>,
    pub e_flags: U32<BigEndian>,
    pub e_ehsize: U16<BigEndian>,
    pub e_phentsize: U16<BigEndian>,
    pub e_phnum: U16<BigEndian>,
    pub e_shentsize: U16<BigEndian>,
    pub e_shnum: U16<BigEndian>,
    pub e_shstrndx: U16<BigEndian>,
}

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawPHdr64Be {
    pub p_type: U32<BigEndian>,
    pub p_flags: U32<BigEndian>,
    pub p_offset: U64<BigEndian>,
    pub p_vaddr: U64<BigEndian>,
    pub p_paddr: U64<BigEndian>,
    pub p_filesz: U64<BigEndian>,
    pub p_memsz: U64<BigEndian>,
    pub p_align: U64<BigEndian>,
}
