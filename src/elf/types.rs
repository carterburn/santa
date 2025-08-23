use zerocopy::*;

pub mod bit32;
pub mod bit64;

pub enum ElfClass {
    Elf32,
    Elf64,
}

pub enum ElfData {
    LittleEndian,
    BigEndian,
}

#[derive(Copy, Clone, Debug)]
pub enum ElfType {
    None,
    Relocatable,
    Executable,
    Shared,
    Core,
    ProcessorSpecific(u16),
}

impl From<u16> for ElfType {
    fn from(value: u16) -> Self {
        use ElfType::*;
        match value {
            0 => None,
            1 => Relocatable,
            2 => Executable,
            3 => Shared,
            4 => Core,
            val => ProcessorSpecific(val),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum ElfMachine {
    None = 0,
    M32 = 1,           // AT&T WE 32100
    Sparc = 2,         // SPARC
    X86 = 3,           // Intel 80386
    M68K = 4,          // Motorola 68000
    M88K = 5,          // Motorola 88000
    IntelMCU = 6,      // Intel MCU
    Intel80860 = 7,    // Intel 80860
    MIPS = 8,          // MIPS I Architecture
    PowerPC = 0x14,    // PowerPC
    PowerPC64 = 0x15,  // PowerPC64
    S390 = 0x16,       // IBM S/390
    Arm = 0x28,        // ARM
    SuperH = 0x2A,     // SuperH
    IA64 = 0x32,       // Intel IA-64
    X86_64 = 0x3E,     // AMD x86-64
    AArch64 = 0xB7,    // ARM AArch64
    RISCV = 0xF3,      // RISC-V
    BPF = 0xF7,        // Linux BPF -- also known as eBPF
    Csky = 0xFE,       // C-SKY
    LoongArch = 0x102, // LoongArch

    Unknown(u16),
}

impl From<u16> for ElfMachine {
    fn from(val: u16) -> Self {
        use ElfMachine::*;
        match val {
            0 => None,
            1 => M32,
            2 => Sparc,
            3 => X86,
            4 => M68K,
            5 => M88K,
            6 => IntelMCU,
            7 => Intel80860,
            8 => MIPS,
            0x14 => PowerPC,
            0x15 => PowerPC64,
            0x16 => S390,
            0x28 => Arm,
            0x2A => SuperH,
            0x32 => IA64,
            0x3E => X86_64,
            0xB7 => AArch64,
            0xF3 => RISCV,
            0xF7 => BPF,
            0xFE => Csky,
            0x102 => LoongArch,
            other => Unknown(other),
        }
    }
}

#[derive(Copy, Clone, Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(u32)]
#[allow(dead_code)]
pub enum PhdrType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Shlib,
    Phdr,
    Tls,
    Num,
    Loos = 0x60000000,
    GnuEhFrame = 0x6474e550,
    GnuStack = 0x6474e551,
    GnuRelro = 0x6474e552,
    GnuProperty = 0x6474e553,
    Losunw = 0x6ffffffa,
    SunwStack = 0x6ffffffb,
    HiSunw = 0x6fffffff,
    LoProc = 0x70000000,
    HiProc = 0x7fffffff,
}

impl From<u32> for PhdrType {
    fn from(value: u32) -> Self {
        use PhdrType::*;
        match value {
            0 => Null,
            1 => Load,
            2 => Dynamic,
            3 => Interp,
            4 => Note,
            5 => Shlib,
            6 => Phdr,
            7 => Tls,
            8 => Num,
            0x60000000 => Loos,
            0x6474e550 => GnuEhFrame,
            0x6474e551 => GnuStack,
            0x6474e552 => GnuRelro,
            0x6474e553 => GnuProperty,
            0x6ffffffa => Losunw,
            0x6ffffffb => SunwStack,
            0x6fffffff => HiSunw,
            0x70000000 => LoProc,
            0x7fffffff => HiProc,
            _ => Null,
        }
    }
}
