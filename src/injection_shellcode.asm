global injection_shellcode_begin, injection_shellcode_end

; since rsp mod 16 must be equal to 8 when a called function starts, it means it must be divisible by 16 before a call (since a call pushes a 8 byte address on the stack)
; our shellcode contains two calls, so it means rsp mod 16 must be equal to 0 when executing it (so that the aligment constraint will be satisfied, otherwise it will crash)

section .text
injection_shellcode_begin:
    nop ;we start our shellcode with some nops because the kernel might move rip for a few bytes if it is interrupted during a syscall
    nop
    nop
    nop
    nop
    jmp load_path_address

shellcode_payload:
    pop rdi ;load our string address inside rdi (first argument)
    xor rsi, rsi
    add sil, 2 ; RTLD_NOW (second argument)
    call rbx ;we are assuming that dlopen address will be stored inside rbx when this shellcode will be called.

    int 3 ;will raise SIGTRAP to notify the injector that the library is loaded

load_path_address:
    call shellcode_payload

injection_shellcode_end: ;our library path will be written here