#include <stdlib.h>
#include <string.h>

#include "shellcodes.h"

void injection_shellcode_begin(void);
void injection_shellcode_end(void);

shellcode_t create_injection_shellcode(const char* library_path)
{
    const size_t library_path_len = strlen(library_path) + 1;

    const uint64_t payload_size = injection_shellcode_end - injection_shellcode_begin;
    const uint64_t shellcode_size = payload_size + library_path_len;
    const uint64_t padding_size = 8 - (shellcode_size % 8);
    const uint64_t final_shellcode_size = shellcode_size + padding_size; 

    uint8_t* modifiable_shellcode = (uint8_t*)malloc(final_shellcode_size);

    memcpy(modifiable_shellcode, injection_shellcode_begin, payload_size); //we start by copying our initial shellcode into writeable memory
    memcpy(modifiable_shellcode + payload_size, library_path, library_path_len); //then we append the library path to our shellcode
    memset(modifiable_shellcode + shellcode_size, 0, padding_size); //and finally, we complete our shellcode with zeroes so that its size is a multiple of 8 bytes (because ptrace writes 8-bytes blocks)

    return (shellcode_t) {.data = modifiable_shellcode, .length = final_shellcode_size, .qwords_count = final_shellcode_size / 8};
}

void ejection_shellcode_begin(void);

#define EJECTION_SHELLCODE_SIZE 8

shellcode_t create_ejection_shellcode(void) //the ejection shellcode is 8-bytes long, so it doesn't require padding
{
    uint8_t* modifiable_shellcode = (uint8_t*)malloc(EJECTION_SHELLCODE_SIZE); //I could just create a fixed array but I want to stay consistent with the previous function
    memcpy(modifiable_shellcode, ejection_shellcode_begin, EJECTION_SHELLCODE_SIZE);

    return (shellcode_t) {.data = modifiable_shellcode, .length = EJECTION_SHELLCODE_SIZE, .qwords_count = EJECTION_SHELLCODE_SIZE / 8};
}