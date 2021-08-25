#include <stdio.h>
#include <stdlib.h>

#include "procutils.h"
#include "shellcodes.h"

typedef void(*regs_edit)(registers_t*);

registers_t* inject_shellcode(pid_t target_pid, shellcode_t shellcode, void* where, regs_edit before_exec)
{
    registers_t* regs = malloc(sizeof(registers_t)); 
    registers_t old_regs;

    attach_process(target_pid);
    get_registers(target_pid, regs);
    get_registers(target_pid, &old_regs);

    uint64_t* current_memory_data = read_memory(target_pid, where, shellcode.qwords_count);
    write_memory(target_pid, where, (uint64_t*)shellcode.data, shellcode.qwords_count);

    before_exec(regs);
    set_registers(target_pid, regs);
    resume_process(target_pid);
    handle_sigtrap(target_pid);

    get_registers(target_pid, regs);
    set_registers(target_pid, &old_regs);
    write_memory(target_pid, where, current_memory_data, shellcode.qwords_count);

    detach_process(target_pid);
    free(current_memory_data);

    return regs;
}

#define ALIGN_RSP(rsp) rsp = rsp - rsp % 16

uint64_t dlopen_address, dlclose_address, executable_memory_zone, lib_handle;

void injection_set_registers(registers_t* tochange)
{
    tochange->rip = executable_memory_zone + 5;
    ALIGN_RSP(tochange->rsp);
    tochange->rbx = dlopen_address;
}

void ejection_set_registers(registers_t* tochange)
{
    tochange->rip = executable_memory_zone+4;
    ALIGN_RSP(tochange->rsp);
    tochange->rbx = dlclose_address;
    tochange->rdi = (uint64_t)lib_handle;
}

int main(int argc, char **argv)
{
    pid_t target_pid = atoi(argv[1]);
    dlopen_address = strtoul(argv[2], NULL, 16);
    dlclose_address = strtoul(argv[3], NULL, 16);
    const char* library_path = "/home/guillaume/Documents/GitHub/Linux64-code-injection/misc/multithreaded_test_so/threaded_lib.so";
    executable_memory_zone = strtoul(argv[5], NULL, 16);

    shellcode_t shellcode = create_injection_shellcode(library_path);
    registers_t* inject_result = inject_shellcode(target_pid, shellcode, (void*)executable_memory_zone, injection_set_registers);

    lib_handle = inject_result->rax;

    free(inject_result);
    free(shellcode.data);

    puts("continuez");
    getchar(); //then we wait until the user writes something

    //now we can run dlclose: we will need to inject another shellcode

    shellcode = create_ejection_shellcode();
    inject_result = inject_shellcode(target_pid, shellcode, (void*)executable_memory_zone, ejection_set_registers);

    puts("j'ai fini");
    
    free(inject_result);
    free(shellcode.data);

    return 0;
}
