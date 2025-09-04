use std::{ffi::c_void, num::NonZeroUsize, ptr::copy_nonoverlapping};

use anyhow::{anyhow, Result};
use goblin::elf::{
    self,
    program_header::{PF_R, PF_W, PF_X, PT_LOAD},
    Elf,
};
use nix::sys::mman::{mmap_anonymous, mprotect, MapFlags, ProtFlags};

pub fn load(elf_bytes: &[u8]) -> Result<(usize, elf::Header, Option<(usize, elf::Header)>)> {
    let elf = Elf::parse(elf_bytes)?;
    let interpreter_path: Option<&str> = elf.interpreter.as_ref().map(|x| x.as_ref());
    let interp = match interpreter_path {
        Some(path) => {
            let bytes = std::fs::read(path)?;
            let (interpreter_addr, interpreter_hdr, None) = load(&bytes)? else {
                panic!()
            };
            Some((interpreter_addr, interpreter_hdr))
        }
        None => None,
    };

    if elf
        .program_headers
        .iter()
        .find(|h| h.p_type == PT_LOAD)
        .ok_or(anyhow!("No PT_LOAD segments"))?
        .p_vaddr
        == 0x00
    {
        load_pie(elf, elf_bytes, interp)
    } else {
        load_non_pie(elf, elf_bytes, interp)
    }
}

fn load_non_pie(
    _elf: Elf,
    _bytes: &[u8],
    _interp: Option<(usize, elf::Header)>,
) -> Result<(usize, elf::Header, Option<(usize, elf::Header)>)> {
    unimplemented!()
}

fn load_pie(
    elf: Elf,
    bytes: &[u8],
    interp: Option<(usize, elf::Header)>,
) -> Result<(usize, elf::Header, Option<(usize, elf::Header)>)> {
    let total_size: usize = elf
        .program_headers
        .iter()
        .filter(|hdr| hdr.p_type == PT_LOAD)
        .map(|h| h.p_vaddr + h.p_memsz)
        .max()
        .ok_or(anyhow!("Unable to compute max address"))?
        .try_into()?;
    let total_size = NonZeroUsize::new(total_size).ok_or(anyhow!("Zero total_size"))?;
    let base_map = unsafe {
        mmap_anonymous(
            None,
            total_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE,
        )?
    };
    let base_addr = base_map.addr().get();
    let (page_floor, page_ceil) = page_adjustments();

    for e in elf
        .program_headers
        .iter()
        .filter(|hdr| hdr.p_type == PT_LOAD)
    {
        let vaddr: usize = e.p_vaddr.try_into()?;
        // where the data actually goes
        let dest = base_addr + vaddr;
        // page-align for mmap call
        let aligned = page_floor(dest);
        let aligned_addr = NonZeroUsize::new(aligned).ok_or(anyhow!("Zero page"))?;
        let align_diff = dest - aligned;
        let length = page_ceil(e.p_memsz as usize + align_diff);
        let length = NonZeroUsize::new(length).ok_or(anyhow!("Zero length"))?;
        let flags = e.p_flags;
        let mut prot = if flags & PF_R != 0 {
            ProtFlags::PROT_READ
        } else {
            ProtFlags::PROT_NONE
        };
        prot |= if flags & PF_W != 0 {
            ProtFlags::PROT_WRITE
        } else {
            ProtFlags::PROT_NONE
        };
        prot |= if flags & PF_X != 0 {
            ProtFlags::PROT_EXEC
        } else {
            ProtFlags::PROT_NONE
        };
        // start with RW always, then mprotect if PF_X is in flags (later on)
        let mapped_addr = unsafe {
            mmap_anonymous(
                Some(aligned_addr),
                length,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            )?
        };

        if e.p_filesz > 0 {
            let dest = unsafe { mapped_addr.add(align_diff) };
            let start = e.p_offset as usize;
            let end = e.p_offset as usize + e.p_filesz as usize;
            let data = &bytes[start..end];
            unsafe {
                copy_nonoverlapping(
                    data.as_ptr(),
                    dest.as_ptr() as *mut u8,
                    e.p_filesz.try_into()?,
                );
            }
        }

        if flags & PF_X != 0 {
            // adjust permissions
            unsafe {
                mprotect(mapped_addr, length.get(), prot)?;
            }
        }
    }

    Ok((base_addr, elf.header, interp))
}

fn page_adjustments() -> (impl Fn(usize) -> usize, impl Fn(usize) -> usize) {
    let page_size: usize = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .unwrap()
        .unwrap()
        .try_into()
        .unwrap();
    let page_floor = move |addr: usize| addr & !(page_size - 1);
    let page_ceil = move |addr: usize| page_floor(addr + page_size - 1);
    (page_floor, page_ceil)
}
