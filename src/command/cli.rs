use std::{ffi::CString, path::Path};

use anyhow::anyhow;
use nix::unistd::Pid;

use crate::{injector, proc_maps, readelf_dynsym, shellcodes, Action};

pub fn cli(
    action: Action,
    pid: Pid,
    dl: String,
    libdl: String,
    dlopen_name: String,
    dlclose_name: String,
) -> anyhow::Result<()> {
    let proc_maps = proc_maps::get_loaded_dl_maps(pid)?;
    
    let dl_absolute_path = std::path::absolute(dl)?.into_os_string().into_string().unwrap();

    let libdl_maps_key = proc_maps.keys().find(|key| key.contains(&libdl)).ok_or(anyhow!("Couldn't find libdl inside the process"))?;
    let libdl_absolute_path = Path::new(libdl_maps_key); 
    
    let libdl_base_addr = proc_maps.get(libdl_maps_key).unwrap()[0].start_address;
    let dlopen_offset = readelf_dynsym::get_fn_offset(libdl_absolute_path, &dlopen_name)?;
    let dlclose_offset = readelf_dynsym::get_fn_offset(libdl_absolute_path, &dlclose_name)?;

    let dlopen_absolute_addr = libdl_base_addr + dlopen_offset;
    let dlclose_absolute_addr = libdl_base_addr + dlclose_offset;

    let mut r#where: u64 = 0;
    for maps in proc_maps.values() {
        for map in maps {
            if map.executable && matches!(map.visibility, proc_maps::MapVisibility::Private) {
                r#where = map.start_address;
                break;
            }
        }
    }

    if r#where == 0 {
        return Err(anyhow!("Error while trying to run a shellcode: couldn't find a suitable zone to inject the shellcode into."));
    }
    
    let dl_absolute_path = &CString::new(dl_absolute_path).unwrap();
    match action {
        Action::Inject => {
            let injection_shellcode = shellcodes::assemble_injection_shellcode(dl_absolute_path, dlopen_absolute_addr)?;
            injector::inject_and_run_shellcode(&injection_shellcode, pid, r#where)?;
        },
        Action::Eject => {
            todo!("fix the ejection shellcode");
        } 
    }

    Ok(())
}