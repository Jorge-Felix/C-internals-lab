default rel

extern GetStdHandle
extern ReadFile
extern WriteFile
extern ExitProcess
section .text
global my_strcmp

; int my_strcmp(const char *s1, const char *s2)
my_strcmp:
    xor rax, rax
.loop:
    mov al, [rcx]
    mov r8b, [rdx]
    
    cmp al, r8b
    jne .dif

    test al, al
    jz .igual

    inc rcx
    inc rdx
    jmp .loop

.dif:
    sub al, r8b
    movsx rax, al
    ret

.igual:
    xor rax, rax
    ret

