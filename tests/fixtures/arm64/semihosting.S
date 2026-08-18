.text
.p2align 2
.globl binobf_semihost_exit
.globl binobf_semihost_write0
.type binobf_semihost_exit, %function
.type binobf_semihost_write0, %function

binobf_semihost_write0:
    mov x1, x0
    mov x0, #4
    hlt #0xf000
    ret

binobf_semihost_exit:
    sub sp, sp, #16
    mov x9, #0x26
    movk x9, #0x2, lsl #16
    str x9, [sp]
    str x0, [sp, #8]
    mov x1, sp
    mov x0, #0x20
    hlt #0xf000
1:
    b 1b
