use std::ffi::c_void;

use anyhow::anyhow;
use nix::libc::user_regs_struct;
use nix::sys::signal::Signal;
use nix::sys::{ptrace, wait};
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use crate::shellcodes::NOPS_COUNT;

pub fn inject_and_run_shellcode(shellcode: &[u8], who: Pid, r#where: u64) -> anyhow::Result<user_regs_struct> {
    //TODO: check that the shellcode:
    //- contains NOPS_COUNT nops at its beginning
    //- its size is a multiple of 8
    
    ptrace::attach(who)?;
    wait::waitpid(who, Some(WaitPidFlag::WUNTRACED))?; //TODO: is WUNTRACED useful here ?

    let registers_backup = ptrace::getregs(who)?;
    let old_rsp = registers_backup.rsp;

    //prepare the new registers, so that rip points to the start of our shellcode and rsp is aligned to 16 bytes
    let registers = user_regs_struct { 
        rip: r#where + NOPS_COUNT as u64, //set the start point to the end of the nops
        rsp: old_rsp - old_rsp % 16, //aligning rsp to 16 bytes to follow System-V ABI 
        ..registers_backup 
    };

    //write our shellcode in r#where
    let memory_area_backup = read_memory(who, r#where, shellcode.len() / 8)?;
    write_memory(who, r#where, shellcode)?;

    ptrace::setregs(who, registers)?;
    ptrace::cont(who, None)?;
    //wait for the target to raise SIGTRAP (meaning the shellcode has been successfully run)
    let wait_status = wait::waitpid(who, Some(WaitPidFlag::WUNTRACED))?; //WUNTRACED is required for testing with WIFSTOPPED
    let WaitStatus::Stopped(who, Signal::SIGTRAP) = wait_status else {
        return Err(anyhow!("Error while trying to wait for the end of the shellcode execution: waitpid failed."));
    };
    //the target is paused; use this opportunity to restore its status using the backups
    let final_registers = ptrace::getregs(who)?;
    ptrace::setregs(who, registers_backup)?;
    write_memory(who, r#where, &memory_area_backup)?;

    ptrace::detach(who, None)?;

    Ok(final_registers)
}

fn read_memory(who: Pid, r#where: u64, bytes_count: usize) -> anyhow::Result<Vec<u8>> {
    let mut result = vec![];

    for i in 0..bytes_count {
        result.push(ptrace::read(who, (r#where + 8 * i as u64) as *mut c_void)?);
    }

    Ok(result.iter().flat_map(|qword| qword.to_le_bytes()).collect())
}

fn write_memory(who: Pid, r#where: u64, bytes: &[u8]) -> anyhow::Result<()> {
    for (i, qword) in bytes.chunks(8).enumerate() {
        ptrace::write(
            who, 
            (r#where + 8 * i as u64) as *mut c_void, 
            i64::from_le_bytes(qword.try_into()?)
        )?;
    }

    Ok(())
}