use std::path::Path;

use anyhow::anyhow;
use elf::{endian::LittleEndian, ElfStream};

pub fn find_function(dl_path: &Path, function_name: &str) -> anyhow::Result<Option<u64>> {
    let elf_file = std::fs::File::open(dl_path)?;
    let mut elf: ElfStream<LittleEndian, _> = ElfStream::open_stream(elf_file)?;

    let Ok(Some((dynsym, dynstr))) = elf.dynamic_symbol_table() else {
        return Err(anyhow!("Error while trying to read {}: could not get the DYNSYM section.", dl_path.to_string_lossy()));
    };

    for symbol in dynsym {
        let symbol_name = dynstr.get(symbol.st_name as usize)?;
        if symbol_name == function_name && symbol.st_symtype() == elf::abi::STT_FUNC && !symbol.is_undefined() {
            return Ok(Some(symbol.st_value));
        }
    }

    Ok(None)
}