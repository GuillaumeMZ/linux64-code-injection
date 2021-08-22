#include <stdio.h>
#include <stdlib.h>

#include "procutils.h"
#include "shellcodes.h"

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
    pid_t target_pid = atoi(argv[1]);
    uint64_t dlopen_address = strtoul(argv[2], NULL, 16);
    uint64_t dlclose_address = strtoul(argv[3], NULL, 16);
    const char* library_path = "/home/guillaume/Documents/lib.so";
    uint64_t executable_memory_zone = strtoul(argv[5], NULL, 16);

    shellcode_t shellcode = create_injection_shellcode(library_path);
    print_memory(shellcode.data, shellcode.length);
    printf("shellcode size: %u => %u qwords and %u remaining bytes\n", shellcode.length, shellcode.length / 8, shellcode.length % 8);

    registers_t regs, old_regs;

    attach_process(target_pid);
    get_registers(target_pid, &regs);
    get_registers(target_pid, &old_regs);

    uint64_t* current_memory_data = read_memory(target_pid, (void*)executable_memory_zone, shellcode.length / 8);
    write_memory(target_pid, (void*)executable_memory_zone, (uint64_t*)shellcode.data, shellcode.length / 8);
    regs.rip = executable_memory_zone+5;
    regs.rsp = regs.rsp - regs.rsp % 16;

    printf("rsp: %lx, rsp mod 16: %lu\n", regs.rsp, regs.rsp % 16);

    regs.rbx = dlopen_address;
    set_registers(target_pid, &regs);
    resume_process(target_pid);
    handle_sigtrap(target_pid);
    get_registers(target_pid, &regs); //now we can extract rax to get dlopen return value
    void* lib_handle = (void*)regs.rax;
    set_registers(target_pid, &old_regs);
    write_memory(target_pid, (void*)executable_memory_zone, current_memory_data, shellcode.length / 8);

    detach_process(target_pid); //aight imma head out
    free(current_memory_data);
    free(shellcode.data);

    puts("continuez");
    getchar(); //then we wait until the user writes something

    //now we can run dlclose: we will need to inject another shellcode
    //we reattach the target
    //same as before
    attach_process(target_pid);
    get_registers(target_pid, &regs); 
    get_registers(target_pid, &old_regs);

    shellcode = create_ejection_shellcode();
    current_memory_data = read_memory(target_pid, (void*)executable_memory_zone, shellcode.length / 8);
    write_memory(target_pid, (void*)executable_memory_zone, (uint64_t*)shellcode.data, shellcode.length / 8);

    regs.rip = executable_memory_zone+5;
    regs.rsp = regs.rsp - regs.rsp % 16;
    regs.rbx = dlclose_address;
    regs.rdi = (uint64_t)lib_handle;

    set_registers(target_pid, &regs);
    resume_process(target_pid);
    handle_sigtrap(target_pid);
    
    set_registers(target_pid, &old_regs);
    write_memory(target_pid, (void*)executable_memory_zone, current_memory_data, shellcode.length / 8);

    detach_process(target_pid);
    puts("j'ai fini");
    
    free(current_memory_data);
    free(shellcode.data);

    return 0;
}
