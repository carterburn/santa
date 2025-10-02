use anyhow::Result;
use nix::{
    libc::{
        getauxval, AT_BASE, AT_CLKTCK, AT_EGID, AT_ENTRY, AT_EUID, AT_EXECFN, AT_FLAGS, AT_GID,
        AT_HWCAP, AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_PLATFORM, AT_RANDOM,
        AT_SECURE, AT_UID,
    },
    sys::mman::{mmap_anonymous, MapFlags, ProtFlags},
    unistd::{getegid, geteuid, getgid, getuid, sysconf, SysconfVar},
};
use std::{
    ffi::{c_void, CStr, CString},
    fmt::Display,
    num::NonZeroUsize,
    ptr::{copy_nonoverlapping, NonNull},
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

pub struct Stack<'a> {
    binary_addr: usize,
    interp: Option<(usize, usize)>,
    file: &'a ElfFile,
    path: &'a str,
    args: &'a [String],
    stack: NonNull<c_void>,
    stack_end: usize,
    reversed: Vec<u8>,
}

impl<'a> Stack<'a> {
    pub fn new(
        binary_addr: usize,
        interp: Option<(usize, usize)>,
        file: &'a ElfFile,
        path: &'a str,
        args: &'a [String],
    ) -> Self {
        let length = 8 * 1024 * 1024;
        let stack = unsafe {
            mmap_anonymous(
                None,
                NonZeroUsize::new(length).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_GROWSDOWN | MapFlags::MAP_STACK,
            )
        }
        .unwrap();

        log::debug!("Allocated stack at {stack:#08x?}");

        let stack_end = stack.addr().get() + length;
        log::debug!("Stack end: {stack_end:#08x}");

        Self {
            binary_addr,
            interp,
            file,
            path,
            args,
            stack,
            stack_end,
            reversed: Vec::new(),
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> usize {
        for b in bytes.iter().rev() {
            self.reversed.push(*b);
        }
        self.stack_end - self.reversed.len()
    }

    fn push_string(&mut self, s: &CStr) -> usize {
        self.push_bytes(s.to_bytes_with_nul())
    }

    fn push_usize(&mut self, val: usize) -> usize {
        self.push_bytes(&val.to_ne_bytes())
    }

    fn push_envp(&mut self) -> Vec<usize> {
        // Push the environment variable strings
        let envp: Vec<CString> = std::env::vars()
            .filter_map(|(key, value)| CString::new(format!("{}={}", key, value)).ok())
            .collect();
        let mut envp_addrs = Vec::with_capacity(envp.len());
        for e in &envp {
            envp_addrs.push(self.push_string(e));
        }
        envp_addrs
    }

    fn push_argv(&mut self, path_addr: usize) -> Vec<usize> {
        let argv: Vec<CString> = self
            .args
            .iter()
            .filter_map(|arg| CString::new(arg.clone()).ok())
            .collect();
        let mut argv_addrs = Vec::with_capacity(argv.len() + 1);
        for a in argv.iter().rev() {
            argv_addrs.push(self.push_string(a));
        }
        // push the path address as the last arg
        argv_addrs.push(path_addr);
        argv_addrs
    }

    fn push_auxv(&mut self, path_addr: usize, at_platform: usize, at_random: usize) -> Result<()> {
        let clktck: usize = (sysconf(SysconfVar::CLK_TCK)?)
            .unwrap_or_default()
            .try_into()?;
        let page_size = (sysconf(SysconfVar::PAGE_SIZE)?)
            .unwrap_or_default()
            .try_into()?;

        let e_entry: usize = self.file.header.e_entry.try_into()?;
        let e_phoff: usize = self.file.header.e_phoff.try_into()?;

        let auxv_rev = [
            (AT_NULL, 0),
            (AT_PLATFORM, at_platform),
            (AT_EXECFN, path_addr),
            (AT_SECURE, unsafe { getauxval(AT_SECURE).try_into()? }),
            (AT_RANDOM, at_random),
            (AT_CLKTCK, clktck),
            (AT_HWCAP, unsafe { getauxval(AT_HWCAP).try_into()? }),
            (AT_EGID, getegid().as_raw().try_into()?),
            (AT_GID, getgid().as_raw().try_into()?),
            (AT_EUID, geteuid().as_raw().try_into()?),
            (AT_UID, getuid().as_raw().try_into()?),
            (AT_ENTRY, self.binary_addr + e_entry),
            (AT_FLAGS, 0),
            (AT_BASE, self.interp.unwrap_or_default().0),
            (AT_PAGESZ, page_size),
            (AT_PHNUM, self.file.header.e_phnum.into()),
            (AT_PHENT, self.file.header.e_phentsize.into()),
            (AT_PHDR, self.binary_addr + e_phoff),
        ];

        for (aux, value) in &auxv_rev {
            let aux: usize = (*aux).try_into()?;
            self.push_usize(*value);
            self.push_usize(aux);
        }

        Ok(())
    }

    pub fn make(&mut self) -> Result<usize> {
        // Push the path of the binary to the base of the stack
        let p: CString = CString::new(self.path)?;
        let path_addr = self.push_string(&p);

        let envp_addrs = self.push_envp();
        let argv_addrs = self.push_argv(path_addr);

        // build out the auxv strings needed
        let at_platform_ptr = unsafe { getauxval(AT_PLATFORM) };
        // convert the pointer to a CString
        let at_platform_str = unsafe { CStr::from_ptr(at_platform_ptr as *const i8) };
        let at_platform_addr = self.push_string(at_platform_str);

        let at_random_ptr = unsafe { getauxval(AT_RANDOM) };
        let at_random_bytes = unsafe { std::slice::from_raw_parts(at_random_ptr as _, 16) };
        let at_random_addr = self.push_bytes(at_random_bytes);

        //     strings                 # of env           # of args      # 2 nulls + argc
        while (self.reversed.len() + (envp_addrs.len() + argv_addrs.len() + 3) * size_of::<usize>())
            % 16
            != 0
        {
            self.reversed.push(0);
        }

        self.push_auxv(path_addr, at_platform_addr, at_random_addr)?;

        // push the envp addresses with a null value in-between
        self.push_usize(0);
        for addr in envp_addrs {
            self.push_usize(addr);
        }

        self.push_usize(0);
        for addr in argv_addrs {
            self.push_usize(addr);
        }

        // add one for path to binary
        self.push_usize(self.args.len() + 1);

        // reverse the stack
        self.reversed.reverse();
        let offset = self.stack_end - self.reversed.len();
        log::debug!("Offset = {offset:#08x}");
        // let stack_pointer = self.stack.addr().get() + offset;
        // log::debug!("sp = {stack_pointer:#08x}");

        unsafe {
            copy_nonoverlapping(
                self.reversed.as_ptr(),
                offset as *mut u8,
                self.reversed.len(),
            )
        }

        Ok(offset)
    }
}
