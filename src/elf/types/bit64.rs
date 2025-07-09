use anyhow::{anyhow, Result};
// Word: U32
// Half: U16
// Addr: U64
// Xword: U64
// Sxword: I64

use std::error::Error;

use zerocopy::{BigEndian, FromBytes, Immutable, KnownLayout, LittleEndian, U16, U32, U64};

use crate::elf::ElfHeader;

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
