default rel 
global memset

section .text
memset:
    push rdi

    mov rax, rcx
    mov rdi, rcx
    mov r9, rcx

    mov al, dl
    mov rcx, r8

    test rcx, rcx
    jz .done

    cld  ; clear direction flag
    rep stosb 


.done:
    pop rdi ; restore original rdi
    ret
