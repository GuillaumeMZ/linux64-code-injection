use nix::unistd::Pid;

use crate::Action;

pub fn cli(
    action: Action,
    pid: Pid,
    dl: String,
    libdl: String,
    dlopen_name: String,
    dlclose_name: String,
) -> anyhow::Result<()> {
    

    Ok(())
}
