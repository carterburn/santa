use core::str;
use std::{
    ffi::CString,
    fs::{self, File},
    io::Write,
    num::NonZeroUsize,
    ptr::copy_nonoverlapping,
    time::Duration,
};

use crate::{
    elf::{types::ElfMachine, ElfFile},
    generator::{codegenx64::CodeGenX64, CodeGen},
    stack::Stack,
};
use anyhow::{anyhow, Result};
use nix::{
    sys::mman::{mmap_anonymous, mprotect, MapFlags, ProtFlags},
    unistd::mkstemp,
};

pub struct ElfExecutor {
    exe: ElfFile,
    name: String,
    interpreter: Option<ElfFile>,
}

impl ElfExecutor {
    pub fn new(file: ElfFile, name: String) -> Result<Self> {
        match file.interp {
            Some(ref i) => {
                let path = i.clone().into_string()?;
                log::debug!("Dynamic executable so loading interpreter from {path}");
                let bytes = fs::read(path)?;
                let interpreter = ElfFile::new(&bytes)?;
                log::debug!("Loaded interpreter successfully");
                Ok(Self {
                    exe: file,
                    name,
                    interpreter: Some(interpreter),
                })
            }
            None => Ok(Self {
                exe: file,
                name,
                interpreter: None,
            }),
        }
    }

    pub fn execute(
        &mut self,
        args: &Vec<String>,
        show_stack: bool,
        show_jumpbuf: bool,
        jump_delay: Option<Duration>,
    ) -> Result<()> {
        let mut stack = Stack::new(2048, self.exe.is_32bit)?;
        let mut argv = vec![CString::new(self.name.clone())?];
        for arg in args {
            argv.push(CString::new(arg.to_string())?);
        }
        let envp: Vec<CString> = std::env::vars()
            .filter_map(|(key, value)| CString::new(format!("{}={}", key, value)).ok())
            .collect();

        let platform = match self.exe.header.e_machine {
            crate::elf::types::ElfMachine::X86 => "x86",
            crate::elf::types::ElfMachine::X86_64 => "x86_64",
            crate::elf::types::ElfMachine::AArch64 => "aarch64",
            _ => unreachable!(),
        }
        .to_string();

        stack.setup(&argv, &envp, &self.exe, &platform, show_stack)?;

        let mut generator = match self.exe.header.e_machine {
            ElfMachine::X86_64 => CodeGen::new(&self.exe, self.interpreter.as_ref(), CodeGenX64)?,
            _ => Err(anyhow!("Unsupported architecture"))?,
        };

        let code = generator.generate(&mut stack, jump_delay)?;

        if show_jumpbuf {
            display_jumpbuf(self.exe.header.e_machine, &code)?;
        }

        // get a new mapping for our jump code to live
        let base = unsafe {
            mmap_anonymous(
                None,
                NonZeroUsize::new(code.len())
                    .ok_or_else(|| anyhow!("A zero size was specified"))?,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_GROWSDOWN,
            )?
        };

        // copy the code to that new base
        unsafe {
            log::debug!(
                "Memmove({:#08x?}, {:#08x?}, {:#08x})",
                code.as_ptr(),
                base.as_ptr(),
                code.len()
            );
            copy_nonoverlapping(code.as_ptr(), base.as_ptr() as *mut u8, code.len());
            let _ = mprotect(
                base,
                code.len(),
                ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
            );
            let fn_ptr: fn() = std::mem::transmute(base.as_ptr());
            fn_ptr();
        }

        Ok(())
    }
}

fn display_jumpbuf(machine: ElfMachine, code: &[u8]) -> Result<()> {
    let machines = std::collections::HashMap::from([
        (ElfMachine::X86, "i386"),
        (ElfMachine::X86_64, "i386:x86-64"),
        (ElfMachine::AArch64, "aarch64"),
    ]);

    let (fd, path) = mkstemp("/tmp/tmpfile_XXXXXX")?;
    {
        let mut file = File::from(fd);
        file.write_all(code)?;
    }

    let cmd = format!(
        "objdump -m {} -b binary -D {:?}",
        machines.get(&machine).ok_or(anyhow!("Invalid machine"))?,
        path
    );
    log::debug!("Executing {cmd}");

    let output = std::process::Command::new("objdump")
        .args([
            "-Mintel",
            "-m",
            machines.get(&machine).ok_or(anyhow!("Invalid machine"))?,
            "-b",
            "binary",
            "-D",
            path.to_str().ok_or(anyhow!("Invalid temp path"))?,
        ])
        .output()?;

    std::fs::remove_file(path)?;

    log::debug!("{}", str::from_utf8(&output.stdout)?);

    Ok(())
}
