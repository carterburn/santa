use anyhow::{anyhow, Result};

use types::{
    bit64::{RawEHdr64Le, RawPHdr64Le},
    ElfClass, ElfData, ElfMachine, ElfType, PhdrType,
};
use zerocopy::FromBytes;

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
pub struct ElfFile<'a> {
    pub header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
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
            (ElfClass::Elf32, ElfData::LittleEndian) => todo!(),
            (ElfClass::Elf32, ElfData::BigEndian) => todo!(),
            (ElfClass::Elf64, ElfData::LittleEndian) => {
                let raw_header =
                    RawEHdr64Le::ref_from_bytes(&elf_bytes[..size_of::<RawEHdr64Le>()])
                        .map_err(|_| anyhow!("Error parsing raw ELF header"))?;
                let header = ElfHeader::parse_64le(raw_header);
                let raw_program_headers = RawPHdr64Le::parse(elf_bytes, &header)
                    .map_err(|_| anyhow!("Error parsing raw program header"))?;
                let program_headers = raw_program_headers
                    .iter()
                    .map(|ph| ProgramHeader::parse_64le(ph))
                    .collect();
                //let program_headers = ProgramHeader::parse_64le(raw_program_headers);
                Ok(Self {
                    header,
                    program_headers,
                })
            }
            (ElfClass::Elf64, ElfData::BigEndian) => todo!(),
        }
    }
}
