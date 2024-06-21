use std::ffi::CStr;

use iced_x86::code_asm::{ptr, rdi, rsi, CodeAssembler};

pub fn assemble_injection_shellcode(dl_path: &CStr, dlopen_address: u64) -> anyhow::Result<Vec<u8>> {
    let mut assembler = CodeAssembler::new(64)?;
    let mut path_beginning = assembler.create_label();

    for _ in 0..5 {
        assembler.nop()?;
    }

    assembler.mov(rdi, ptr(path_beginning))?; //first argument to dlopen
    assembler.mov(rsi, 2u64)?; //RTLD_NOW (second argument)
    assembler.call(dlopen_address)?;

    assembler.int3()?; //raise SIGTRAP to notify the injector the library has been injected

    assembler.set_label(&mut path_beginning)?;
    assembler.db(dl_path.to_bytes_with_nul())?; //write the path inside the shellcode

    Ok(assembler.assemble(0)?)
}

pub fn assemble_ejection_shellcode(dl_handle: u64, dlclose_address: u64) -> anyhow::Result<Vec<u8>> {
    let mut assembler = CodeAssembler::new(64)?;

    for _ in 0..5 {
        assembler.nop()?;
    }

    assembler.mov(rdi, dl_handle)?; //dlclose first argument (the dl address)
    assembler.call(dlclose_address)?;

    assembler.int3()?;

    Ok(assembler.assemble(0)?)
}