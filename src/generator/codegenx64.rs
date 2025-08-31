// Derived from ulexecve (https://github.com/anvilsecure/ulexecve)
// Copyright (c) 2021-2023 Anvil Secure Inc.
// Licensed under the BSD-3-Clause License
// See the LICENSE file in the repository root for the license disclaimer.
use std::time::Duration;

use crate::stack::Stack;

use super::CodeGenerator;

pub struct CodeGenX64;

/*
 * Assembly code snippets were taken verbatim from ulexecve.py referenced in the README and LICENSE.
 * These snippets are pretty straightforward, just taking in arguments and calling various system
 * calls or doing memcpy in assembly.
 */

impl CodeGenerator for CodeGenX64 {
    fn mmap(&self, addr: usize, length: usize, prot: u32, flags: u32, offset: usize) -> Vec<u8> {
        let fd: u32 = 0xffffffff;
        let offset: u32 = offset.try_into().unwrap_or(0);
        let mut code = Vec::with_capacity(62);
        code.extend_from_slice(b"\x48\xc7\xc0\x09\x00\x00\x00\x48\xbf");
        code.extend_from_slice(&addr.to_le_bytes());
        code.extend_from_slice(b"\x48\xbe");
        code.extend_from_slice(&length.to_le_bytes());
        code.extend_from_slice(b"\x48\xc7\xc2");
        code.extend_from_slice(&prot.to_le_bytes());
        code.extend_from_slice(b"\x49\xc7\xc2");
        code.extend_from_slice(&flags.to_le_bytes());
        code.extend_from_slice(b"\x49\xc7\xc0");
        code.extend_from_slice(&fd.to_le_bytes());
        code.extend_from_slice(b"\x49\xc7\xc1");
        code.extend_from_slice(&offset.to_le_bytes());
        //code.extend_from_slice(b"\x0f\x05\x50\x4c\x8b\x1c\x24");
        code.extend_from_slice(b"\x0f\x05\x50\x4c\x8b\x24\x24");

        log::debug!("Generated mmap call (addr={addr:#08x}, length={length:#08x}, prot={prot:#x}, flags={flags:#x})");
        code
    }

    fn munmap(&self, addr: usize, length: usize) -> Vec<u8> {
        let mut code = Vec::with_capacity(29);
        code.extend_from_slice(b"\x48\xc7\xc0\x0b\x00\x00\x00\x48\xbf");
        code.extend_from_slice(&addr.to_le_bytes());
        code.extend_from_slice(b"\x48\xbe");
        code.extend_from_slice(&length.to_le_bytes());
        code.extend_from_slice(b"\x0f\x05");
        code
    }

    fn mprotect(&self, addr: usize, length: usize, prot: u32) -> Vec<u8> {
        let mut code = Vec::with_capacity(36);
        code.extend_from_slice(b"\x48\xc7\xc0\x0a\x00\x00\x00\x48\xbf");
        code.extend_from_slice(&addr.to_le_bytes());
        code.extend_from_slice(b"\x48\xbe");
        code.extend_from_slice(&length.to_le_bytes());
        code.extend_from_slice(b"\x48\xc7\xc2");
        code.extend_from_slice(&prot.to_le_bytes());
        code.extend_from_slice(b"\x0f\x05");
        code
    }

    fn generate_jumpcode(
        &self,
        stack: &mut Stack,
        entry_ptr: usize,
        tls: Option<usize>,
        jump_delay: Option<Duration>,
    ) -> Vec<u8> {
        let mut code = Vec::new();
        if let Some(dur) = jump_delay {
            code.extend_from_slice(b"\x6a\x00\x68");
            code.extend_from_slice(&dur.subsec_nanos().to_le_bytes());
            code.extend_from_slice(
                b"\x48\x89\xe7\x48\xc7\xc0\x23\x00\x00\x00\x41\x53\x0f\x05\x41\x5b",
            );
        }
        // if there is a TLS segment, set the fs_base register before we do this
        if let Some(tls_addr) = tls {
            code.extend_from_slice(
                b"\x48\xc7\xc0\x9e\x00\x00\x00\x48\xc7\xc7\x02\x10\x00\x00\x48\xbe",
            );
            code.extend_from_slice(&tls_addr.to_le_bytes());
            code.extend_from_slice(b"\x0f\x05");
        }
        let regs = [0xc0, 0xdb, 0xc9, 0xd2, 0xed, 0xe4, 0xf6, 0xff];
        for reg in regs {
            code.extend_from_slice(b"\x48\x31");
            code.push(reg);
        }
        code.extend_from_slice(b"\x48\xbc");
        let stack_ptr = stack.base().addr();
        code.extend_from_slice(&stack_ptr.get().to_le_bytes());
        code.extend_from_slice(b"\x48\xb9");
        // since this is x64, this will be a u64, but on x86, we'll need to move to u32
        code.extend_from_slice(&entry_ptr.to_le_bytes());
        //code.extend_from_slice(b"\x4c\x01\xd9\x48\x31\xd2\xff\xe1");
        code.extend_from_slice(b"\x4c\x01\xe1\x48\x31\xd2\xff\xe1");

        log::debug!("Jumpbuf with entry %r11+{entry_ptr:#08x} and stack: {stack_ptr:#16x?}");
        code
    }

    fn memcpy_from_offset(&self, offset: usize, src: usize, sz: usize) -> Vec<u8> {
        let mut code = Vec::with_capacity(35);
        code.extend_from_slice(b"\x48\xbe");
        code.extend_from_slice(&src.to_le_bytes());
        code.extend_from_slice(b"\x48\xbf");
        code.extend_from_slice(&offset.to_le_bytes());
        //code.extend_from_slice(b"\x4c\x01\xdf\x48\xb9");
        code.extend_from_slice(b"\x4c\x01\xe7\x48\xb9");
        code.extend_from_slice(&sz.to_le_bytes());
        code.extend_from_slice(b"\xf3\xa4");

        log::debug!(
            "Generated memcpy call (dst=%r11 + {offset:#08x}, src={src:#08x}, size={sz:#08x})"
        );
        code
    }

    fn generate_auxv_fixup(
        &self,
        stack: &mut Stack,
        auxv_offset: usize,
        map_offset: usize,
        relative: bool,
    ) -> Vec<u8> {
        let auxv_ptr = stack.base().addr().get() + stack.auxv_start() + (auxv_offset << 3);
        let mut code = Vec::with_capacity(26);
        code.extend_from_slice(b"\x49\xbe");
        code.extend_from_slice(&map_offset.to_le_bytes());
        if relative {
            //code.extend_from_slice(b"\x4d\x01\xde");
            code.extend_from_slice(b"\x4d\x01\xe6");
        }
        code.extend_from_slice(b"\x49\xbf");
        code.extend_from_slice(&auxv_ptr.to_le_bytes());
        code.extend_from_slice(b"\x4d\x89\x37");
        code
    }

    fn fill_zero(&self, offset: usize, sz: usize) -> Vec<u8> {
        let mut code = Vec::new();
        code.extend_from_slice(b"\x48\xbf");
        code.extend_from_slice(&offset.to_le_bytes());
        //code.extend_from_slice(b"\x4c\x01\xdf\x48\xb9");
        code.extend_from_slice(b"\x4c\x01\xe7\x48\xb9");
        code.extend_from_slice(&sz.to_le_bytes());
        code.extend_from_slice(b"\x48\x31\xc0\xf3\xaa");
        code
    }
}
