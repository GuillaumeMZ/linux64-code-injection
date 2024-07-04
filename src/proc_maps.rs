use std::collections::HashMap;

use anyhow::Context;
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use regex::Regex;
 
#[derive(Clone, Debug)]
pub enum MapVisibility {
    Private,
    Shared,
}
 
#[derive(Clone, Debug)]
pub struct ProcessMapSection {
    pub start_address: u64,
    pub end_address:   u64,
    pub readable:      bool,
    pub writable:      bool,
    pub executable:    bool,
    pub visibility:    MapVisibility,
    pub offset:        usize,
    pub device_major:  u8,
    pub device_minor:  u8,
    pub inode:         u64,
    pub name:          String, //we ignore unnamed mappings: this is why this is not an option<string>
}
 
pub type ProcessMapSections = HashMap<String, Vec<ProcessMapSection>>;

pub fn get_loaded_dl_maps(pid: Pid) -> anyhow::Result<ProcessMapSections> {
    let mappings_path = &format!("/proc/{}/maps", pid.as_raw());
    let raw_contents = std::fs::read_to_string(mappings_path)
        .context(format!("Error: could not open {}. Are you sure {} is a valid process id ?", mappings_path, pid.as_raw()))?;
 
    Ok(raw_contents
        .lines()
        .filter_map(parse_proc_maps_line)
        .map(|it| (it.name.clone(), it))
        .fold(ProcessMapSections::new(), |mut mappings, (name, mapping)| {
            mappings.entry(name.clone()).or_default().push(mapping.clone());
            mappings
        })
    )
}

static MAPPING_REGEX: Lazy<Regex> = Lazy::new(|| {
    let hex = "[0-9a-f]+";
    let regex = format!(r"({hex})-({hex}) (r|-)(w|-)(x|-)(p|s) ({hex}) (\d+):(\d+) (\d+)\s+(.+\.so.*)");

    Regex::new(&regex).unwrap() //shouldn't fail
});

fn parse_proc_maps_line(line: &str) -> Option<ProcessMapSection> {
    //None of the following unwrap()s can fail, because the regex already did the validation job
    MAPPING_REGEX
        .captures(line)
        .map(|c| c.extract::<11>()) //11 attributes in the ProcessMapSection struct
        .map(|(_, groups)| ProcessMapSection {
            start_address: u64::from_str_radix(groups[0], 16).unwrap(),
            end_address:   u64::from_str_radix(groups[1], 16).unwrap(),
            readable:      groups[2] == "r",
            writable:      groups[3] == "w",
            executable:    groups[4] == "x",
            visibility:    if groups[5] == "p" { MapVisibility::Private } else { MapVisibility::Shared },
            offset:        usize::from_str_radix(groups[6], 16).unwrap(),
            device_major:  groups[7].parse().unwrap(),
            device_minor:  groups[8].parse().unwrap(),
            inode:         groups[9].parse().unwrap(),
            name:          groups[10].to_owned(),
        })
}
