default rel

;size_t strlen(const char *str);
section .text
global optistrlen
optistrlen:
    mov rdi, rcx
    mov r9, rcx

    xor al, al
    mov rcx, -1

    cld  ; clear df

    repne scasb 

    sub rdi, r9
    dec rdi

    mov rax, rdi
    ret
