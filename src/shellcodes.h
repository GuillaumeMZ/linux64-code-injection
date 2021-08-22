#include <stdint.h>

typedef struct {
    uint8_t* data;
    size_t length;
    size_t qwords_count;
} shellcode_t;

shellcode_t create_injection_shellcode(const char* library_path);
shellcode_t create_ejection_shellcode(void);