use std::{ffi::CString, fs, pin::Pin};

use crate::elf::{
    types::{ElfMachine, ElfType, PhdrType},
    ElfFile, ElfHeader, ProgramHeader,
};
use anyhow::{anyhow, Result};

pub struct ElfExecutor<'a> {
    exe: ElfFile<'a>,
    ibytes: Box<Vec<u8>>,
    interpreter: Option<ElfFile<'a>>,
}

impl<'a> ElfExecutor<'a> {
    pub fn new(file: ElfFile<'a>) -> Result<(Vec<u8>, Self)> {
        match file.interp {
            Some(ref i) => {
                let path = i.clone().into_string()?;
                let bytes = fs::read(path)?;
                let boxed = Box::new(bytes);
                let interpreter = ElfFile::new(&boxed)?;
                Ok((
                    bytes,
                    Self {
                        exe: file,
                        ibytes: boxed,
                        interpreter: Some(interpreter),
                    },
                ))
            }
            None => Ok((
                vec![],
                Self {
                    exe: file,
                    ibytes: Box::new(vec![]),
                    interpreter: None,
                },
            )),
        }
    }
}
