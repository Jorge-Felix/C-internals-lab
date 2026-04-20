default rel

section .text
global strlen
strlen:
    xor rax, rax        ; zero rax
.loop:
    cmp byte [rcx + rax], 0
    je .done
    inc rax
    jmp .loop
.done:
    ret