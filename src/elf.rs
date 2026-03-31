use std::{ffi::CString, fmt::Display};

use anyhow::{anyhow, Result};

use types::{
    bit64::{parse_elf64, RawEHdr64Le, RawPHdr64Le},
    ElfClass, ElfData, ElfMachine, ElfType, PhdrType,
};

pub mod types;

#[derive(Debug)]
pub struct ElfHeader {
    pub e_ident: [u8; 16],
    pub e_type: ElfType,
    pub e_machine: ElfMachine,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl ElfHeader {
    pub fn parse_64le(raw: &RawEHdr64Le) -> Self {
        let e_type = raw.e_type.get().into();
        let e_machine = raw.e_machine.get().into();

        ElfHeader {
            e_ident: raw.e_ident,
            e_type,
            e_machine,
            e_version: raw.e_version.get(),
            e_entry: raw.e_entry.get(),
            e_phoff: raw.e_phoff.get(),
            e_shoff: raw.e_shoff.get(),
            e_flags: raw.e_flags.get(),
            e_ehsize: raw.e_ehsize.get(),
            e_phentsize: raw.e_phentsize.get(),
            e_phnum: raw.e_phnum.get(),
            e_shentsize: raw.e_shentsize.get(),
            e_shnum: raw.e_shnum.get(),
            e_shstrndx: raw.e_shstrndx.get(),
        }
    }
}

#[derive(Debug)]
pub struct ProgramHeader {
    pub p_type: PhdrType,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl ProgramHeader {
    pub fn parse_64le(raw: &RawPHdr64Le) -> Self {
        Self {
            p_type: raw.p_type.get().into(),
            p_flags: raw.p_flags.get(),
            p_offset: raw.p_offset.get(),
            p_vaddr: raw.p_vaddr.get(),
            p_paddr: raw.p_paddr.get(),
            p_filesz: raw.p_filesz.get(),
            p_memsz: raw.p_memsz.get(),
            p_align: raw.p_align.get(),
        }
    }
}

#[derive(Debug)]
pub struct Segment {
    pub header: ProgramHeader,
    pub data: Vec<u8>,
}

impl Segment {
    pub fn new(header: ProgramHeader, elf_bytes: &[u8]) -> Self {
        let start = header.p_offset as usize;
        let end = header.p_offset as usize + header.p_filesz as usize;
        let data = elf_bytes[start..end].to_vec();

        log::debug!(
            "PT_LOAD at offset 0x{:08x}: flags=0x{:x}, vaddr=0x{:x}, filesz=0x{:x}, memsz=0x{:x}",
            header.p_offset,
            header.p_flags,
            header.p_vaddr,
            header.p_filesz,
            header.p_memsz
        );

        Self { header, data }
    }
}

#[derive(Debug)]
pub struct ElfFile {
    pub header: ElfHeader,
    pub segments: Vec<Segment>,
    pub pie: bool,
    pub interp: Option<CString>,
    pub is_32bit: bool,
}

impl ElfFile {
    pub fn new(elf_bytes: &[u8]) -> Result<Self> {
        let e_ident = &elf_bytes[..16];
        if e_ident[0..4] != [0x7F, b'E', b'L', b'F'] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Not an ELF file",
            ))?;
        }

        let class = match e_ident[4] {
            1 => ElfClass::Elf32,
            2 => ElfClass::Elf64,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ELF class",
                ))?
            }
        };

        let data = match e_ident[5] {
            1 => ElfData::LittleEndian,
            2 => ElfData::BigEndian,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid ELF data encoding",
                ))?
            }
        };

        match (class, data) {
            (ElfClass::Elf32, ElfData::LittleEndian) => unimplemented!(),
            (ElfClass::Elf32, ElfData::BigEndian) => unimplemented!(),
            (ElfClass::Elf64, ElfData::LittleEndian) => parse_elf64(elf_bytes),
            (ElfClass::Elf64, ElfData::BigEndian) => unimplemented!(),
        }
    }

    pub fn memory_size(&self) -> Result<usize> {
        let mut size = 0;
        for segment in &self.segments {
            let (vaddr, memsz) = (segment.header.p_vaddr, segment.header.p_memsz);
            size = if (vaddr + memsz) > size {
                vaddr + memsz
            } else {
                size
            };
        }

        if !self.pie {
            let adjustment = self
                .segments
                .first()
                .ok_or(anyhow!("No segments in ELF"))?
                .header
                .p_vaddr;
            log::debug!("Not a PIE binary so adjusting size down with {adjustment:08x}");
            size -= adjustment;
        }
        log::debug!("Total calculated memory size: {size:08x?}");

        Ok(size.try_into()?)
    }
}

impl Display for ElfFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self.header)?;
        for segment in &self.segments {
            writeln!(f, "{:?}", segment.header)?;
        }
        writeln!(f, "PIE: {}", self.pie)?;
        writeln!(f, "Interpreter: {:?}", self.interp)
    }
}
