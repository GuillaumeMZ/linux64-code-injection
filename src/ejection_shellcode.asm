global ejection_shellcode_begin

;this shellcode should be 8 bytes long

section .text
ejection_shellcode_begin:
    nop
    nop
    nop
    nop
    call rbx ; we are assuming that rbx contains dlclose address (and that rdi contains the handle address)
    int 3