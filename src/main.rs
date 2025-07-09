use std::{error::Error, fs};

use santa::{elf::ElfFile, executor::ElfVerifier};

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = fs::read("/bin/echo")?;

    let elf = ElfFile::new(&bytes).map_err(|e| e.to_string())?;
    let verified = ElfVerifier::parse(&bytes, &elf)?;

    //println!("{verified:?}");

    println!(
        "{}",
        if verified.pie {
            "Identified as a PIE executable"
        } else {
            "Not a PIE"
        }
    );

    match verified.interp {
        Some(i) => println!("Dynamic executable so loading interpreter from {i:?}"),
        None => println!("Not a dynamic executable"),
    }

    for segment in verified.segments.iter().filter(|segment| {
        matches!(
            segment.header.p_type,
            santa::elf::types::PhdrType::Load | santa::elf::types::PhdrType::Interp
        )
    }) {
        match segment.header.p_type {
            santa::elf::types::PhdrType::Load => {
                println!("PT_LOAD at offset 0x{:08x}: flags=0x{:x}, vaddr=0x{:x}, filesz=0x{:x}, memsz=0x{:x}",
                    segment.header.p_offset,
                    segment.header.p_flags,
                    segment.header.p_vaddr,
                    segment.header.p_filesz,
                    segment.header.p_memsz);
                println!("Verified Header: {:?}", segment.header);
            }
            santa::elf::types::PhdrType::Interp => {
                println!(
                    "PT_INTERP at offset 0x{:08x}: interpreter printed earlier.",
                    segment.header.p_offset
                );
            }
            _ => {}
        }
    }

    /*
    let header = Elf64Ehdr::ref_from_bytes(&elf[..size_of::<Elf64Ehdr>()]).unwrap();
    println!("{header:?}");

    let ph_offset: usize = header.e_phoff.get().try_into().unwrap();
    let phdr_sz: usize = size_of::<Elf64Phdr>();

    for i in 0..header.e_phnum.get() as usize {
        let index: usize = ph_offset + (phdr_sz * i);

        println!(
            "{:?}",
            Elf64Phdr::try_ref_from_bytes(&elf[index..index + size_of::<Elf64Phdr>()]).unwrap()
        );
    }
    */

    Ok(())
}
