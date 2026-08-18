    .text
    .globl _start
_start:
    movl $20, %edi
    movl $1, %esi
    call archive_add
    movl %eax, %edi
    call archive_double
    movl %eax, %edi
    movl $60, %eax
    syscall
