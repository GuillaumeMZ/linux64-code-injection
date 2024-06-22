use std::ffi::CStr;

use iced_x86::code_asm::{ptr, rdi, rsi, rbx, CodeAssembler};

pub fn assemble_injection_shellcode(dl_path: &CStr, dlopen_address: u64) -> anyhow::Result<Vec<u8>> {
    let mut assembler = CodeAssembler::new(64)?;
    
    let mut shellcode_payload = assembler.create_label();
    let mut load_path_address = assembler.create_label();

    for _ in 0..5 {
        assembler.nop()?;
    }
    assembler.jmp(load_path_address)?;

    assembler.set_label(&mut shellcode_payload)?;
    assembler.pop(rdi)?; //first argument to dlopen
    assembler.mov(rsi, 2u64)?; //RTLD_NOW (second argument)
    assembler.mov(rbx, dlopen_address)?;
    assembler.call(rbx)?;

    assembler.int3()?; //raise SIGTRAP to notify the injector the library has been injected

    assembler.set_label(&mut load_path_address)?;
    assembler.call(shellcode_payload)?;

    assembler.db(dl_path.to_bytes_with_nul())?; //write the path inside the shellcode

    Ok(pad_shellcode(&assembler.assemble(0)?))
}

pub fn assemble_ejection_shellcode(dl_handle: u64, dlclose_address: u64) -> anyhow::Result<Vec<u8>> {
    let mut assembler = CodeAssembler::new(64)?;

    for _ in 0..5 {
        assembler.nop()?;
    }

    assembler.mov(rdi, dl_handle)?; //dlclose first argument (the dl address)
    assembler.mov(rbx, dlclose_address)?;
    assembler.call(rbx)?;

    assembler.int3()?;

    Ok(pad_shellcode(&assembler.assemble(0)?))
}

fn pad_shellcode(shellcode: &Vec<u8>) -> Vec<u8> {
    let padding_bytes_count = 8 - (shellcode.len() % 8);
    
    [shellcode.as_slice(), &[0u8].repeat(padding_bytes_count)].concat() //unclear one-liner
}