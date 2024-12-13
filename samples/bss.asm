; in `elk/samples/bss.asm`

        global _start

        section .text

_start: ; load address of `zero`, for debugging purposes
        lea rax, [rel zero]

        ; then just exit.
        xor rdi, rdi
        mov rax, 60
        syscall

        section .bss

        ; here it is!
zero:   resq 16