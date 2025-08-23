use anyhow::{anyhow, Result};
use nix::{
    libc::memset,
    sys::mman::{mmap_anonymous, MapFlags, ProtFlags},
    unistd::{getegid, geteuid, getgid, getuid},
};
use std::{
    collections::HashMap,
    ffi::{c_char, c_void, CString},
    fmt::Display,
    num::NonZeroUsize,
    ptr::NonNull,
    rc::Rc,
    str::FromStr,
};

use crate::elf::ElfFile;

#[derive(Debug, Hash, PartialEq, Eq)]
#[repr(u32)]
enum AuxValues {
    AtNull = 0,
    AtPhdr = 3,
    AtPhent = 4,
    AtPhnum = 5,
    AtPagesz = 6,
    AtBase = 7,
    AtEntry = 9,
    AtUid = 11,
    AtEuid = 12,
    AtGid = 13,
    AtEgid = 14,
    AtPlatform = 15,
    AtHwcap = 16,
    AtClktck = 17,
    AtSecure = 23,
    AtRandom = 25,
    AtHwcap2 = 26,
    AtExecfn = 31,
    AtSysinfo = 32,
    AtSysinfoEhdr = 33,
    AtMinsigstksz = 51,
}

impl Display for AuxValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use AuxValues::*;
        write!(
            f,
            "{}",
            match self {
                AtNull => "AT_NULL",
                AtPhdr => "AT_PHDR",
                AtPhent => "AT_PHENT",
                AtPhnum => "AT_PHNUM",
                AtPagesz => "AT_PAGESZ",
                AtBase => "AT_BASE",
                AtEntry => "AT_ENTRY",
                AtUid => "AT_UID",
                AtEuid => "AT_EUID",
                AtGid => "AT_GID",
                AtEgid => "AT_EGID",
                AtPlatform => "AT_PLATFORM",
                AtHwcap => "AT_HWCAP",
                AtClktck => "AT_CLKTCK",
                AtSecure => "AT_SECURE",
                AtRandom => "AT_RANDOM",
                AtHwcap2 => "AT_HWCAP2",
                AtExecfn => "AT_EXECFN",
                AtSysinfo => "AT_SYSINFO",
                AtSysinfoEhdr => "AT_SYSINFO_EHDR",
                AtMinsigstksz => "AT_MINSIGSTKSZ",
            }
        )
    }
}

impl From<AuxValues> for u64 {
    fn from(value: AuxValues) -> Self {
        use AuxValues::*;
        match value {
            AtNull => 0,
            AtPhdr => 3,
            AtPhent => 4,
            AtPhnum => 5,
            AtPagesz => 6,
            AtBase => 7,
            AtEntry => 9,
            AtUid => 11,
            AtEuid => 12,
            AtGid => 13,
            AtEgid => 14,
            AtPlatform => 15,
            AtHwcap => 16,
            AtClktck => 17,
            AtSecure => 23,
            AtRandom => 25,
            AtHwcap2 => 26,
            AtExecfn => 31,
            AtSysinfo => 32,
            AtSysinfoEhdr => 33,
            AtMinsigstksz => 51,
        }
    }
}

impl From<u64> for AuxValues {
    fn from(value: u64) -> Self {
        use AuxValues::*;
        match value {
            0 => AtNull,
            3 => AtPhdr,
            4 => AtPhent,
            5 => AtPhnum,
            6 => AtPagesz,
            7 => AtBase,
            9 => AtEntry,
            11 => AtUid,
            12 => AtEuid,
            13 => AtGid,
            14 => AtEgid,
            15 => AtPlatform,
            16 => AtHwcap,
            17 => AtClktck,
            23 => AtSecure,
            25 => AtRandom,
            26 => AtHwcap2,
            31 => AtExecfn,
            32 => AtSysinfo,
            33 => AtSysinfoEhdr,
            51 => AtMinsigstksz,
            _ => AtNull,
        }
    }
}

impl From<AuxValues> for usize {
    fn from(value: AuxValues) -> Self {
        use AuxValues::*;
        match value {
            AtNull => 0,
            AtPhdr => 3,
            AtPhent => 4,
            AtPhnum => 5,
            AtPagesz => 6,
            AtBase => 7,
            AtEntry => 9,
            AtUid => 11,
            AtEuid => 12,
            AtGid => 13,
            AtEgid => 14,
            AtPlatform => 15,
            AtHwcap => 16,
            AtClktck => 17,
            AtSecure => 23,
            AtRandom => 25,
            AtHwcap2 => 26,
            AtExecfn => 31,
            AtSysinfo => 32,
            AtSysinfoEhdr => 33,
            AtMinsigstksz => 51,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum StackOffsets {
    OffsetAtBase = 1,
    OffsetAtPhdr = 3,
    OffsetAtEntry = 5,
}

impl From<StackOffsets> for usize {
    fn from(value: StackOffsets) -> Self {
        use StackOffsets::*;
        match value {
            OffsetAtBase => 1,
            OffsetAtPhdr => 3,
            OffsetAtEntry => 5,
        }
    }
}

pub struct Stack {
    size: usize,
    base: NonNull<c_void>,
    stack: &'static mut [usize],
    is_32bit: bool,
    auxv_start: usize,
}

impl Stack {
    pub fn new(num_pages: usize, is_32bit: bool) -> Result<Self> {
        let page_size: usize = Self::get_page_size()?;
        let size = page_size * num_pages;
        let mut base = unsafe {
            mmap_anonymous(
                None,
                NonZeroUsize::new(size).ok_or_else(|| anyhow!("A zero size was specified"))?,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_GROWSDOWN,
            )?
        };
        log::debug!("Initial base: {base:08x?}");

        unsafe { memset(base.as_mut(), 0, size) };

        base = unsafe { base.add(size - page_size) };
        // create an array from this base address
        let stack = unsafe {
            std::slice::from_raw_parts_mut(
                base.as_ptr() as *mut usize,
                page_size / size_of::<usize>(),
            )
        };

        log::debug!("Stack allocated at {base:08x?} ({:08x?})", stack.as_ptr());

        Ok(Self {
            size,
            base,
            stack,
            is_32bit,
            auxv_start: 0,
        })
    }

    pub fn raw_stack(&mut self) -> &mut [usize] {
        self.stack
    }

    pub fn base(&self) -> NonNull<c_void> {
        self.base
    }

    pub fn get_page_size() -> Result<usize> {
        Ok(nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)?
            .ok_or_else(|| anyhow!("Could not retrieve system page size"))?
            .try_into()?)
    }

    pub fn setup(
        &mut self,
        argv: &Vec<CString>,
        envp: &Vec<CString>,
        exe: &ElfFile,
        platform: &str,
        show_stack: bool,
    ) -> Result<()> {
        self.stack[0] = argv.len();
        let mut i = 1;
        for arg in argv {
            self.stack[i] = arg.as_ptr().addr();
            i += 1;
        }
        self.stack[i + 1] = 0;
        let env_off = i + 1;

        i = 0;
        for env in envp {
            self.stack[env_off + i] = env.as_ptr().addr();
            i += 1;
        }
        self.stack[env_off + i] = 0;
        i += 1;

        let aux_off = i + env_off;
        self.auxv_start = aux_off << (if self.is_32bit { 2 } else { 3 });
        let end_off = self.setup_auxv(aux_off, exe, platform)?;

        log::debug!("end_off: {end_off}");
        self.show_stack(env_off, aux_off, end_off, show_stack)
    }

    pub fn auxv_start(&self) -> usize {
        self.auxv_start
    }

    fn show_stack(
        &self,
        env_off: usize,
        aux_off: usize,
        end_off: usize,
        show_stack: bool,
    ) -> Result<()> {
        if !show_stack {
            return Ok(());
        }
        log::debug!("stack contents:");
        for i in 0..aux_off {
            log::debug!(
                " {:08x}:   0x{:016x} ({})",
                i * 8,
                self.stack[i],
                if i < env_off { "argv" } else { "envp" }
            );
        }

        for i in (aux_off..end_off).step_by(2) {
            log::debug!(
                " {:08x}:   0x{:016x} 0x{:016x} ({})",
                i * 8,
                self.stack[i],
                self.stack[i + 1],
                AuxValues::from(self.stack[i] as u64),
            )
        }

        Ok(())
    }

    fn setup_auxv(&mut self, mut aux_off: usize, exe: &ElfFile, platform: &str) -> Result<usize> {
        let auxv_keys = vec![
            AuxValues::AtSysinfoEhdr.into(),
            AuxValues::AtSysinfo.into(),
            AuxValues::AtClktck.into(),
            AuxValues::AtHwcap.into(),
            AuxValues::AtHwcap2.into(),
        ];
        let auxvs: HashMap<AuxValues, u64> = auxv::procfs::search_procfs_auxv(auxv_keys.as_slice())
            .unwrap_or_default()
            .iter()
            .map(|(key, value)| ((*key).into(), *value))
            .collect();

        // the value at self.stack[1]
        let at_execfn = self.stack[1];
        let aux_start = unsafe { self.base.add(aux_off).addr() };

        let mut auxv: Vec<(AuxValues, usize)> = vec![
            (AuxValues::AtBase, 0x0),
            (AuxValues::AtPhdr, 0x0),
            (AuxValues::AtEntry, 0x0),
            (AuxValues::AtPhnum, exe.header.e_phnum.into()),
            (AuxValues::AtPhent, exe.header.e_phentsize.into()),
            (AuxValues::AtPagesz, Self::get_page_size()?),
            (AuxValues::AtSecure, 0),
            (AuxValues::AtRandom, aux_start.get()), // XXX now just points to start of aux
            (
                AuxValues::AtSysinfo,
                (*(auxvs.get(&AuxValues::AtSysinfo).unwrap_or(&0))).try_into()?,
            ),
            (
                AuxValues::AtSysinfoEhdr,
                (*(auxvs.get(&AuxValues::AtSysinfoEhdr).unwrap_or(&0))).try_into()?,
            ),
            (AuxValues::AtPlatform, platform.as_ptr().addr()),
            (AuxValues::AtExecfn, at_execfn),
            (AuxValues::AtUid, getuid().as_raw().try_into()?),
            (AuxValues::AtEuid, geteuid().as_raw().try_into()?),
            (AuxValues::AtGid, getgid().as_raw().try_into()?),
            (AuxValues::AtEgid, getegid().as_raw().try_into()?),
        ];

        if let Some(clktck) = auxvs.get(&AuxValues::AtClktck) {
            auxv.push((AuxValues::AtClktck, (*clktck).try_into()?));
        }

        if let Some(hwcap) = auxvs.get(&AuxValues::AtHwcap) {
            auxv.push((AuxValues::AtHwcap, (*hwcap).try_into()?));
        }

        if let Some(hwcap2) = auxvs.get(&AuxValues::AtHwcap2) {
            auxv.push((AuxValues::AtHwcap2, (*hwcap2).try_into()?));
        }

        auxv.push((AuxValues::AtNull, 0));

        for (aux_type, aux_val) in auxv {
            self.stack[aux_off] = aux_type.into();
            self.stack[aux_off + 1] = aux_val;
            aux_off += 2;
        }
        aux_off -= 1;

        Ok(aux_off)
    }
}
