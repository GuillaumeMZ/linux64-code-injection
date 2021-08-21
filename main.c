#include <stdio.h>
#include <stdlib.h>

#include "procutils.h"
#include "shellcode.h"

void print_memory(const uint8_t* addr, size_t sz)
{
    for(size_t i = 0; i < sz; ++i)
    {
        printf("\\x%.2x", addr[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    //uint8_t exit_shellcode[] = "\x90\x90\x48\x31\xc0\x04\x3c\x48\x31\xff\x40\x80\xc7\x7b\x0f\x05"; //2B, sys_exit(123)

    //code de test pour check si libc_dlopen_mode fonctionne
    //code de test en asm pour vérifier dlopen avec pop et stack bien alignée
    //revoir l'alignment de rsp
    //utiliser le core dump pour debug (vérifier que tout est écrit)
    //si rien ne fonctionne => essayer avec dlopen
    //nouvelle stack frame? (en théorie non nécessaire)

    pid_t target_pid = atoi(argv[1]);
    uint64_t function_address = strtoul(argv[2], NULL, 16);
    const char* library_path = "/home/guillaume/Documents/lib.so";
    uint64_t executable_memory_zone = strtoul(argv[4], NULL, 16);

    shellcode_t shellcode = create_shellcode(function_address, library_path);
    print_memory(shellcode.data, shellcode.length);
    printf("shellcode size: %u => %u qwords and %u remaining bytes\n", shellcode.length, shellcode.length / 8, shellcode.length % 8);

    registers_t regs;

    attach_process(target_pid);
    get_registers(target_pid, &regs);

    write_memory(target_pid, (void*)executable_memory_zone, (uint64_t*)shellcode.data, shellcode.length / 8);
    regs.rip = executable_memory_zone+5;
    regs.rsp = regs.rsp - regs.rsp % 16;

    printf("rsp: %lx, rsp mod 16: %lu", regs.rsp, regs.rsp % 16);

    set_registers(target_pid, &regs);
    resume_process(target_pid);

    puts("j'ai fini");
    
    //free(readmem);
    free(shellcode.data);

    return 0;
}
