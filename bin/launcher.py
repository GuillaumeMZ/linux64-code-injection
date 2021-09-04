#!/usr/bin/python3

import argparse
import pathlib
import re
import subprocess
import sys

parser = argparse.ArgumentParser(prog='launcher.py', description='Inject and execute code from a shared object into a process.')
parser.add_argument('-p', '--pid', required=True, type=int, help='The process ID of the target.')
parser.add_argument('-l', '--lib_path', required=True, type=pathlib.Path, help='The path of the library to inject into the target process (it may be either relative or absolute).')
parser.add_argument('-d', '--dlfcn_provider', required=False, choices=['libc', 'libdl'], default='libc', help='Which dlopen implementation should be used to inject the shared object (default is libc).')
parser.add_argument('-c', '--check_after_injection', required=False, action='store_true', help='After the injector has finished, check if the library is still injected inside the process.')

args = parser.parse_args()
pid = args.pid
lib_path = str(args.lib_path.resolve())
provider_name = args.dlfcn_provider
check_after_injection = args.check_after_injection

def file_exists(file_path):
    file_info = pathlib.Path(file_path)
    return file_info.exists() and file_info.is_file()

#ensuring the target and the injectable .so both exist
assert file_exists(f'/proc/{pid}/maps'), 'The target process doesn\'t exist !'
assert file_exists(lib_path), 'The injectable shared object doesn\'t exist !'

def read_mappings(pid):
    with open(f'/proc/{pid}/maps', 'r') as mapping:
        return mapping.read()

def find_mapped_zone_if(mapping, pred):
    for line in mapping.split('\n'):
        if(pred(line)):
            return line

    assert False, 'Mapping wasn\'t found.'

def get_mapped_zone_address(mapped_zone_line):
    output = re.split(r'\s+', mapped_zone_line)
    return int(output[0].split('-')[0], 16)

def get_mapped_zone_path(mapped_zone_line):
    output = re.split(r'\s', mapped_zone_line)
    return output[-1] 

mappings = read_mappings(pid)

#Reads /proc/pid/info to locate dlfcn provider library path and its mapping address inside the target memory space
def get_provider_info(mappings, provider_name):
    mapped_zone = find_mapped_zone_if(mappings, lambda s : provider_name in s)

    return get_mapped_zone_path(mapped_zone), get_mapped_zone_address(mapped_zone)
    
#getting dlfcn provider's path and loading address
provider_path, provider_mapping_addr = get_provider_info(mappings, provider_name)

readelf_process = subprocess.run(['readelf', '-s', provider_path], capture_output=True)
readelf_output = str(readelf_process.stdout).split(r'\n')

def get_function_offset(readelf_output, function_name):
    for line in readelf_output:
        if function_name in line and 'FUNC' in line and 'GLOBAL' in line:
            output = re.split(r'\s+', line)
            return output[2]

    assert False, f'Function {function_name} wasn\'t found.'

dlopen_func_name = 'dlopen' if provider_name == 'libdl' else '__libc_dlopen_mode'
dlclose_func_name = 'dlclose' if provider_name == 'libdl' else '__libc_dlclose'

#getting dlopen and dlclose (or libc_dlopen_mode and libc_dlclose) offsets
dlopen_offset = get_function_offset(readelf_output, dlopen_func_name)
dlclose_offset = get_function_offset(readelf_output, dlclose_func_name)

#computing dlopen/__libc_dlopen_mode and dlclose/__libc_dlclose absolute addresses
dlopen_absolute_addr = provider_mapping_addr + int(dlopen_offset, 16)
dlclose_absolute_addr = provider_mapping_addr + int(dlclose_offset, 16)

#Finding a memory zone with execution permission so we can write shellcodes there
executable_memzone = get_mapped_zone_address(find_mapped_zone_if(mappings, lambda s : 'r-xp' in s))

#calling the injector
subprocess.run(['./injector', str(pid), str(hex(dlopen_absolute_addr)), str(hex(dlclose_absolute_addr)), lib_path, str(hex(executable_memzone))])

def is_library_loaded(pid, library_name):
    with open(f'/proc/{pid}/maps', 'r') as proc_maps:
        return any(library_name in line for line in proc_maps)

#assert that the injected library is loaded (optional)
if check_after_injection:
    assert is_library_loaded(pid, lib_path), f'{lib_path} isn\'t loaded inside process {pid}.'