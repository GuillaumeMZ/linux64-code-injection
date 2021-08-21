global shellcode_begin, shellcode_end

; since rsp mod 16 must be equal to 8 when a called function starts, it means it must be divisible by 16 before a call (since a call pushes a 8 byte address on the stack)
; our shellcode contains only a call, so it means rsp mod 16 must equal 0 when executing it (so that the aligment constraint will be satisfied, oterwise it will crash)

section .text
shellcode_begin:
    nop
    nop
    nop
    nop
    nop
    jmp load_path_address

shellcode_payload:
    mov rbx, 0x1122334455667788 ; placeholder address, will be replaced by our injector
    mov rdi, [rsp] ;load our string address inside rdi (first argument) | we don't use pop to respect the aforementioned constraint about rsp alignment
    mov rsi, 2 ; RTLD_NOW (second argument)
    call rbx

    ;int 3
    
    ;à supprimer
    mov rax, 60
    mov rdi, 123
    syscall ;exit

load_path_address:
    call shellcode_payload

shellcode_end: ;our library path will be written here