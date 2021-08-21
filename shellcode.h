#include <stdint.h>

typedef struct {
    uint8_t* data;
    size_t length;
} shellcode_t;

shellcode_t create_shellcode(uint64_t dlopen_address, const char* library_path);