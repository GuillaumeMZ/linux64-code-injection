use std::path::Path;

use anyhow::{anyhow, Context};
use elf::{endian::LittleEndian, ElfStream};

pub fn find_function(dl_path: &Path, function_name: &String) -> anyhow::Result<u64> {
    let dl_path_str = dl_path.to_string_lossy();

    let elf_file = std::fs::File::open(dl_path).context(format!(
        concat!(
            "Error while trying to find the {} function in {}:",
            "could not open {}. Are you sure it exists ?"
        ),
        function_name, 
        dl_path_str, 
        dl_path_str
    ))?;

    let mut elf: ElfStream<LittleEndian, _> = ElfStream::open_stream(elf_file).context(format!(
        concat!(
            "Error while trying to find the {} function in {}:",
            "failed to parse {}. Are you sure it is a valid ELF64 shared library ?"
        ),
        function_name,
        dl_path_str,
        dl_path_str
    ))?;

    let Ok(Some((dynsym, dynstr))) = elf.dynamic_symbol_table() else {
        return Err(anyhow!(
            concat!(
                "Error while trying to find the {} function in {}:",
                "could not get the DYNSYM section.",
                "Are you sure that {} is a dynamic library ?"
            ),
            function_name,
            dl_path_str,
            dl_path_str
        ));
    };

    for symbol in dynsym {
        let symbol_name = dynstr.get(symbol.st_name as usize).context(format!(
            concat!(
                "Error while trying to find the {} function in {}:",
                "failed to parse an entry of the dynsym section.",
                "Are you sure that {} is not corrupted ?"
            ),
            function_name,
            dl_path_str,
            dl_path_str
        ))?;

        if symbol_name == function_name && symbol.st_symtype() == elf::abi::STT_FUNC && !symbol.is_undefined() {
            return Ok(symbol.st_value);
        }
    }

    Err(anyhow!(format!(
        concat!(
            "Error while trying to find the {} function in {}:",
            "could not find it, even though everything else went fine.",
            "Are you sure {} is not misspelled ?"
        ),
        function_name, dl_path_str, function_name
    )))
}
