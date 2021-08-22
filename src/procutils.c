#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>

#include "procutils.h"
#include "utils.h"

#define PTRACE_ERROR -1
#define WAITPID_ERROR -1

void attach_process(pid_t pid)
{
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == PTRACE_ERROR)
        fatal_error("attach_process (ptrace)");
    
    if(waitpid(pid, NULL, WUNTRACED) == -1)
        fatal_error("attach_process (waitpid)");
}

void detach_process(pid_t pid)
{
    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == PTRACE_ERROR)
        fatal_error("detach_process");
}

void resume_process(pid_t pid)
{
    if(ptrace(PTRACE_CONT, pid, NULL, NULL) == PTRACE_ERROR)
        fatal_error("resume_process");
}


void resume_process_singlestep(pid_t pid)
{
    if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == PTRACE_ERROR)
        fatal_error("resume_process_singlestep (ptrace)");

    int status_result;
    if(waitpid(pid, &status_result, WUNTRACED) == WAITPID_ERROR)
        fatal_error("resume_process_singlestep (waitpid)");

    if(!WIFSTOPPED(status_result) || WSTOPSIG(status_result) != SIGTRAP)
        fatal_error("resume_process_singlestep (process hasn't stopped or signal is not SIGTRAP)");
}

void handle_sigtrap(pid_t pid)
{
    int status_result;
    if(waitpid(pid, &status_result, WUNTRACED) == WAITPID_ERROR)
        fatal_error("handle_sigtrap (waitpid)");

    if(!WIFSTOPPED(status_result) || WSTOPSIG(status_result) != SIGTRAP)
        fatal_error("handle_sigtrap (process hasn't stopped or signal is not SIGTRAP)");
}

void get_registers(pid_t pid, registers_t* save)
{
    if(ptrace(PTRACE_GETREGS, pid, NULL, save) == PTRACE_ERROR)
        fatal_error("get_registers");
}

void set_registers(pid_t pid, const registers_t* registers)
{
    if(ptrace(PTRACE_SETREGS, pid, NULL, registers) == PTRACE_ERROR)
        fatal_error("set_registers");
}

uint64_t* read_memory(pid_t pid, void* address, size_t words_to_read)
{
    uint64_t* mem = (uint64_t*)malloc(sizeof(uint64_t[words_to_read]));

    for(size_t offset = 0; offset < words_to_read; ++offset)
    {
        errno = 0;
        mem[offset] = ptrace(PTRACE_PEEKDATA, pid, address + sizeof(uint64_t) * offset, NULL); //-1 && errno != 0 => error
        
        if(errno != 0 && mem[offset] == -1)
            fatal_error("read_memory");
    }
 
    return mem;
}

void write_memory(pid_t pid, void* address, const uint64_t* buffer, size_t buffer_size)
{
    for(size_t offset = 0; offset < buffer_size; ++offset)
        if(ptrace(PTRACE_POKEDATA, pid, address + sizeof(uint64_t) * offset, buffer[offset]) == PTRACE_ERROR)
            fatal_error("write_memory");
}