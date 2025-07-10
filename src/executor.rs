use std::{ffi::CString, fs, pin::Pin};

use crate::elf::{
    types::{ElfMachine, ElfType, PhdrType},
    ElfFile, ElfHeader, ProgramHeader,
};
use anyhow::{anyhow, Result};

pub struct ElfExecutor {
    exe: ElfFile,
    interpreter: Option<ElfFile>,
}

impl ElfExecutor {
    pub fn new(file: ElfFile) -> Result<Self> {
        match file.interp {
            Some(ref i) => {
                let path = i.clone().into_string()?;
                log::debug!("Dynamic executable so loading interpreter from {path}");
                let bytes = fs::read(path)?;
                let interpreter = ElfFile::new(&bytes)?;
                log::debug!("Loaded interpreter successfully");
                Ok(Self {
                    exe: file,
                    interpreter: Some(interpreter),
                })
            }
            None => Ok(Self {
                exe: file,
                interpreter: None,
            }),
        }
    }
}
