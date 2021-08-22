#include <stdlib.h>
#include <string.h>

#include "shellcode.h"

#define SHELLCODE_ADDRESS_OFFSET 9

void shellcode_begin(void);
void shellcode_end(void);

shellcode_t create_shellcode(uint64_t dlopen_address, const char* library_path)
{
    const size_t library_path_len = strlen(library_path) + 1;

    const uint64_t payload_size = shellcode_end - shellcode_begin;
    const uint64_t shellcode_size = payload_size + library_path_len;
    const uint64_t padding_size = 8 - (shellcode_size % 8);
    const uint64_t final_shellcode_size = shellcode_size + padding_size; 

    uint8_t* modifiable_shellcode = (uint8_t*)malloc(final_shellcode_size);

    memcpy(modifiable_shellcode, shellcode_begin, payload_size); //we start by copying our initial shellcode into writeable memory
    memcpy(modifiable_shellcode + SHELLCODE_ADDRESS_OFFSET, &dlopen_address, sizeof(uint64_t)); //then we replace the placeholder address with the address we got from the script
    memcpy(modifiable_shellcode + payload_size, library_path, library_path_len); //then we append the library path to our shellcode
    memset(modifiable_shellcode + shellcode_size, 0, padding_size); //and finally, we complete our shellcode with zeroes so that its size is a multiple of 8 bytes (because ptrace writes 8-bytes blocks)

    return (shellcode_t) {.data = modifiable_shellcode, .length = final_shellcode_size};
}