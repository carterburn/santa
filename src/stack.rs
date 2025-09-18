use anyhow::{anyhow, Result};
use nix::{
    libc::memset,
    sys::mman::{mmap_anonymous, MapFlags, ProtFlags},
    unistd::{getegid, geteuid, getgid, getuid},
};
use std::{
    collections::HashMap,
    ffi::{c_void, CString},
    fmt::Display,
    num::NonZeroUsize,
    ptr::NonNull,
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
    interp: Option<usize>,
    path: &'a String,
    args: &'a [String],
    stack_end: usize,
    reversed: Vec<u8>,
}

impl<'a> Stack<'a> {
    pub fn new(
        binary_addr: usize,
        interp: Option<usize>,
        path: &'a String,
        args: &'a [String],
    ) -> Self {
        let length = 8 * 1024 * 1024;
        let stack = unsafe {
            mmap_anonymous(
                None,
                NonZeroUsize::new(length).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_GROWSDOWN | MapFlags::MAP_STACK,
            )
        }
        .unwrap();

        let stack_end = stack.addr().get() + length;

        Self {
            binary_addr,
            interp,
            path,
            args,
            stack_end,
            reversed: Vec::new(),
        }
    }
}
