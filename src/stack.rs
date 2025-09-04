use anyhow::{anyhow, Result};
use goblin::elf;
use nix::{
    libc::{AT_NULL, AT_PLATFORM},
    sys::mman::{mmap_anonymous, MapFlags, ProtFlags},
};
use std::{
    ffi::{CStr, CString},
    num::NonZero,
};

struct Stack<'a> {
    interp_addr: Option<usize>,
    bin_addr: usize,
    bin_header: elf::Header,
    path: &'a CStr,
    args: &'a [String],
    stack_end_addr: usize,
    data: Vec<usize>,
}

impl<'a> Stack<'a> {
    fn new(
        interp_addr: Option<usize>,
        bin_addr: usize,
        bin_header: elf::Header,
        path: &'a CStr,
        args: &'a [String],
        stack_end_addr: usize,
    ) -> Self {
        let data = vec![];
        Stack {
            interp_addr,
            bin_addr,
            bin_header,
            path,
            args,
            stack_end_addr,
            data,
        }
    }

    fn push_str(&mut self, s: &CStr) {
        // convert s to byte slice and convert to usize
        let bytes = s.to_bytes_with_nul();
        for chunk in bytes.chunks(std::mem::size_of::<usize>()) {
            let mut buffer = [0u8; std::mem::size_of::<usize>()];
            buffer[..chunk.len()].copy_from_slice(chunk);
            self.data.push(usize::from_ne_bytes(buffer));
        }
    }

    fn make(&mut self) -> Result<Vec<usize>> {
        // collect environment variables
        let env_strs: Vec<CString> = std::env::vars()
            .filter_map(|(key, value)| CString::new(format!("{}={}", key, value)).ok())
            .collect();

        // argc at the top of the stack
        self.data.push(self.args.len());
        let argv_offset = self.data.len();
        // push 0's for argv addresses for now
        for _ in 0..self.args.len() {
            self.data.push(0);
        }

        // start envp pointers
        self.data.push(0);
        let envp_offset = self.data.len(); // where envp offsets start
        for _ in 0..env_strs.len() {
            self.data.push(0);
        }

        self.data.push(0);
        // start auxv
        let auxv_offset = self.data.len();

        // this is a nightmare, we may need to think through this more on the algo

        // auxv strings
        // argv strings
        // envp strings
        // path of executable string

        /*
        // add strings to the stack
        // executable path
        self.push_str(self.path);


        let mut envp_addrs = vec![];
        for var in envp {
            envp_addrs.push(self.push_str(&var));
        }

        // argv text
        let mut arg_addrs = Vec::new();
        for arg in self.args.iter() {
            arg_addrs.push(self.push_str(&CString::new(arg.as_str())?));
        }
        */
    }
}

pub fn make_stack(
    interp_addr: Option<usize>,
    bin_addr: usize,
    bin_header: elf::Header,
    path: &CStr,
    args: &[String],
) -> Result<usize> {
    let stack_size = 1024 * 1024 * 10;

    let stack = unsafe {
        mmap_anonymous(
            None,
            NonZero::new(stack_size).ok_or(anyhow!("Invalid stack_size"))?,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_GROWSDOWN | MapFlags::MAP_STACK,
        )?
    };

    let stack_end_addr: usize = stack.addr().get() + stack_size;

    let data = {
        let stack = Stack::new(
            interp_addr,
            bin_addr,
            bin_header,
            path,
            args,
            stack_end_addr,
        );
        stack.make()?
    };
}
