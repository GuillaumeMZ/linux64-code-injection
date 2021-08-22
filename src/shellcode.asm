global shellcode_begin, shellcode_end

; since rsp mod 16 must be equal to 8 when a called function starts, it means it must be divisible by 16 before a call (since a call pushes a 8 byte address on the stack)
; our shellcode contains two calls, so it means rsp mod 16 must be equal to 0 when executing it (so that the aligment constraint will be satisfied, otherwise it will crash)

section .text
shellcode_begin:
    nop ;we start our shellcode with some nops because the kernel might move rip for a few bytes if it is interrupted during a syscall
    nop
    nop
    nop
    nop
    jmp load_path_address

shellcode_payload:
    mov rbx, 0x1122334455667788 ; placeholder address, will be replaced by our injector
    pop rdi ;load our string address inside rdi (first argument)
    mov rsi, 2 ; RTLD_NOW (second argument)
    call rbx

    int 3 ;will raise SIGTRAP to notify the injector that the library is loaded

load_path_address:
    call shellcode_payload

shellcode_end: ;our library path will be written here