use std::{arch::asm, num::NonZeroUsize, ptr::copy_nonoverlapping};

use crate::{elf::ElfFile, stack::Stack};
use anyhow::{anyhow, Result};
use nix::{
    libc::{PF_R, PF_W, PF_X},
    sys::mman::{mmap_anonymous, mprotect, MapFlags, ProtFlags},
};

pub fn load(file: &ElfFile) -> Result<(usize, Option<(usize, usize)>)> {
    let interp_addr = match &file.interp {
        Some(path) => {
            let path = path.clone().into_string()?;
            let bytes = std::fs::read(path)?;
            let interpreter = ElfFile::new(&bytes)?;
            let (interp_addr, _) = load(&interpreter)?;
            Some((interp_addr, interpreter.header.e_entry.try_into()?))
        }
        None => None,
    };

    // load based on if the binary is a PIE or non-PIE binary
    if file.pie {
        load_pie(file, interp_addr)
    } else {
        load_non_pie(file, interp_addr)
    }
}

pub fn load_pie(
    file: &ElfFile,
    interp_addr: Option<(usize, usize)>,
) -> Result<(usize, Option<(usize, usize)>)> {
    let total_size: usize = file
        .segments
        .iter()
        .map(|h| h.header.p_vaddr + h.header.p_memsz)
        .max()
        .ok_or(anyhow!("Unable to compute total size required"))?
        .try_into()?;

    let total_size = NonZeroUsize::new(total_size).ok_or(anyhow!("Got zero for total size"))?;

    let base_map = unsafe {
        mmap_anonymous(
            None,
            total_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE,
        )?
    };
    let base_addr = base_map.addr().get();
    let page_size: usize = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)?
        .ok_or(anyhow!("No PAGE_SIZE given"))?
        .try_into()?;
    let page_floor = move |addr: usize| addr & !(page_size - 1);
    let page_ceil = move |addr: usize| page_floor(addr + page_size - 1);

    // loop through each segment, overmapping at the specified vaddr
    for segment in &file.segments {
        let vaddr: usize = segment.header.p_vaddr.try_into()?;
        let memsz: usize = segment.header.p_memsz.try_into()?;
        // where in memory this actually goes
        let dest = vaddr + base_addr;
        let aligned = page_floor(dest);
        let align_diff = dest - aligned;
        let map_length = page_ceil(memsz + align_diff);
        let aligned_addr = NonZeroUsize::new(aligned).ok_or(anyhow!("Invalid aligned_addr"))?;
        let length = NonZeroUsize::new(map_length).ok_or(anyhow!("Invalid map_length"))?;
        let mapping = unsafe {
            // start with PROT_READ | PROT_WRITE and adjust as necessary after data exists
            mmap_anonymous(
                Some(aligned_addr),
                length,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            )?
        };
        log::debug!(
            "Loading PT_LOAD at map={:#08x}, vaddr={vaddr:#08x}",
            mapping.addr().get()
        );

        // copy over data to destination within the new mapping
        if segment.header.p_filesz > 0 {
            let dst = unsafe { mapping.add(align_diff) };
            assert!(dst.addr().get() == dest);
            unsafe {
                copy_nonoverlapping(
                    segment.data.as_ptr(),
                    dst.as_ptr() as *mut u8,
                    segment.data.len(),
                );
            }
        }

        // adjust permissions
        let mut prot = ProtFlags::PROT_NONE;
        if segment.header.p_flags & PF_R != 0 {
            prot |= ProtFlags::PROT_READ;
        }
        if segment.header.p_flags & PF_W != 0 {
            prot |= ProtFlags::PROT_WRITE;
        }
        if segment.header.p_flags & PF_X != 0 {
            prot |= ProtFlags::PROT_EXEC;
        }

        unsafe { mprotect(mapping, map_length, prot)? }
    }

    Ok((base_addr, interp_addr))
}

// A non-pie file will have a base address of 0 because the entry point of the
// non-pie file will be a virtual address
pub fn load_non_pie(
    file: &ElfFile,
    interp_addr: Option<(usize, usize)>,
) -> Result<(usize, Option<(usize, usize)>)> {
    // TODO: get these closures to be returned by a function somewhere
    let page_size: usize = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)?
        .ok_or(anyhow!("No PAGE_SIZE given"))?
        .try_into()?;
    let page_floor = move |addr: usize| addr & !(page_size - 1);
    let page_ceil = move |addr: usize| page_floor(addr + page_size - 1);

    for segment in &file.segments {
        let vaddr: usize = segment.header.p_vaddr.try_into()?;
        let memsz: usize = segment.header.p_memsz.try_into()?;
        let aligned = page_floor(vaddr);
        let align_diff = vaddr - aligned;
        let map_length = page_ceil(memsz + align_diff);
        let aligned_addr = NonZeroUsize::new(aligned).ok_or(anyhow!("Invalid aligned_addr"))?;
        let length = NonZeroUsize::new(map_length).ok_or(anyhow!("Invalid map_length"))?;
        let mapping = unsafe {
            mmap_anonymous(
                Some(aligned_addr),
                length,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            )?
        };
        log::debug!(
            "Loading PT_LOAD at map={:#08x}, vaddr={vaddr:#08x}",
            mapping.addr().get()
        );

        if segment.header.p_filesz > 0 {
            let dst = unsafe { mapping.add(align_diff) };
            assert!(dst.addr().get() == vaddr);
            unsafe {
                copy_nonoverlapping(
                    segment.data.as_ptr(),
                    dst.as_ptr() as *mut u8,
                    segment.data.len(),
                );
            }
        }

        // adjust permissions TODO: make this a function for a new segment
        let mut prot = ProtFlags::PROT_NONE;
        if segment.header.p_flags & PF_R != 0 {
            prot |= ProtFlags::PROT_READ;
        }
        if segment.header.p_flags & PF_W != 0 {
            prot |= ProtFlags::PROT_WRITE;
        }
        if segment.header.p_flags & PF_X != 0 {
            prot |= ProtFlags::PROT_EXEC;
        }
        unsafe { mprotect(mapping, map_length, prot)? }
    }

    Ok((0, interp_addr))
}

pub fn exec(file: &ElfFile, args: &[String], path: &str) -> Result<()> {
    // interp = Option<(usize, usize)> -> (interp_base, interp_entry)
    let (base_addr, interp) = load(file)?;

    let mut stack = Stack::new(base_addr, interp, file, path, args);
    let sp = stack.make()?;

    let entry = match interp {
        Some((interp_base, interp_entry)) => interp_base + interp_entry,
        None => {
            let entry: usize = file.header.e_entry.try_into()?;
            base_addr + entry
        }
    };

    unsafe { run(entry, sp) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn run(entry: usize, sp: usize) -> ! {
    unsafe {
        asm! {
            "mov rsp, {sp}",
            "jmp {entry}",
            inout("rax") 0 => _,
            sp = in(reg) sp,
            entry = in(reg) entry,
        }
    }
    unreachable!();
}

#[cfg(target_arch = "aarch64")]
unsafe fn run(entry: usize, sp: usize) -> ! {
    unsafe {
        asm! {
            "mov sp, {sp}",
            "br {entry}",
            sp = in(reg) sp,
            entry = in(reg) entry,
        }
    }
    unreachable!()
}
