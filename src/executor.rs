use std::fs;

use crate::{elf::ElfFile, stack::Stack};
use anyhow::Result;

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

    pub fn execute(&mut self, args: &Vec<String>) -> Result<()> {
        let mut stack = Stack::new(2048, self.exe.is_32bit)?;
        let mut argv = vec![self.name.clone()];
        for arg in args {
            argv.push(arg.to_string());
        }
        let envp: Vec<String> = std::env::vars()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect();

        let platform = match self.exe.header.e_machine {
            crate::elf::types::ElfMachine::X86 => "x86",
            crate::elf::types::ElfMachine::X86_64 => "x86_64",
            crate::elf::types::ElfMachine::AArch64 => "aarch64",
            _ => unreachable!(),
        }
        .to_string();

        stack.setup(&argv, &envp, &self.exe, &platform, true)?;

        //std::thread::sleep(std::time::Duration::from_secs(20));

        log::debug!("Break here");

        Ok(())
    }
}
