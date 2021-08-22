#!/bin/bash

pid=$1
func_name=$2
lib_name=$3

if [ ! -d /proc/$pid ]; then
  echo "Error: The given PID is incorrect."
  exit 1
fi

# Get the map of process and get the line that correspond to the executable section of libc
line=$(grep $lib_name /proc/$pid/maps | head -n 1)

if [ -z "$line" ]; then
  echo "Error: The given pid doesn't have $lib_name loaded, or it wasn't found."
  exit 1
fi

# Extract the base address of that section and the name of the library
lib_baseaddr=$(echo $line | cut -d "-" -f1)
echo "[+] Found $lib_name at $lib_baseaddr"
lib_path=$(echo $line | rev | cut -d ' ' -f1 | rev) # extract the last field

# Use readelf to find the offset of the function
function_offset=$(readelf -s $lib_path | grep $func_name | head -n 1 | sed 's/^[ \t]*//' | cut -d ' ' -f2) # extract the 2nd field
echo "[+] Found $func_name offset = $function_offset"

# Compute the actual addresses
function_addr=$(expr $(printf "%d" 0x$lib_baseaddr) + $(printf "%d" 0x$function_offset))
function_addr_hex=$(printf "0x%x" $function_addr)

echo "[+] Found $func_name at $function_addr_hex"

echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

memzone_line=$(grep r-xp /proc/$pid/maps | head -n 1)
memzone_addr=$(echo $memzone_line | cut -d "-" -f1)

echo "[+] Found executable memory region at $memzone_addr" 

./injector $pid $function_addr_hex $lib_path $memzone_addr
echo "return value: $?"

echo 2 | sudo tee /proc/sys/kernel/yama/ptrace_scope