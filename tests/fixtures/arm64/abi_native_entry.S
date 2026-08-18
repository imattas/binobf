.text
.p2align 2
.globl _start
.globl binobf_arm64_abi_target
.globl binobf_arm64_mixed_target
.globl binobf_arm64_indirect_target
.type _start, %function
.type binobf_arm64_abi_target, %function
.type binobf_arm64_mixed_target, %function
.type binobf_arm64_indirect_target, %function

_start:
    mrs x9, cpacr_el1
    orr x9, x9, #(3 << 20)
    msr cpacr_el1, x9
    isb
    adrp x9, __stack_top
    add x9, x9, :lo12:__stack_top
    mov sp, x9
    bl binobf_arm64_run_once
    mov x10, #4097
    cmp x0, x10
    b.ne binobf_arm64_failed_integer_one

    sub sp, sp, #16
    bl binobf_arm64_run_once
    add sp, sp, #16
    mov x10, #4097
    cmp x0, x10
    b.ne binobf_arm64_failed_integer_two

    bl binobf_arm64_run_mixed
    cmp x0, #23
    b.ne binobf_arm64_failed_mixed

    bl binobf_arm64_run_indirect
    cmp x0, #100
    b.ne binobf_arm64_failed_indirect
    adr x0, binobf_arm64_pass_message
    bl binobf_semihost_write0
    mov x0, #0
    b binobf_semihost_exit

binobf_arm64_failed_integer_one:
    adr x0, binobf_arm64_integer_one_message
    b binobf_arm64_report_failure
binobf_arm64_failed_integer_two:
    adr x0, binobf_arm64_integer_two_message
    b binobf_arm64_report_failure
binobf_arm64_failed_mixed:
    adr x0, binobf_arm64_mixed_message
    b binobf_arm64_report_failure
binobf_arm64_failed_indirect:
    adr x0, binobf_arm64_indirect_message
binobf_arm64_report_failure:
    bl binobf_semihost_write0
    mov x0, #0
    b binobf_semihost_exit

binobf_arm64_run_once:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    sub sp, sp, #16
    mov x0, #2
    mov x1, #1
    mov x2, #3
    mov x3, #4
    mov x4, #5
    mov x5, #6
    mov x6, #7
    mov x7, #8
    mov x8, #9
    str x8, [sp]
    bl binobf_arm64_abi_adapter
    mov sp, x29
    ldp x29, x30, [sp], #16
    ret

binobf_arm64_run_mixed:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x9, #0x4008
    lsl x9, x9, #48
    fmov d1, x9
    mov x10, #5
    fmov d0, x10
    mov x10, #7
    ins v0.d[1], x10
    mov x1, #11
    bl binobf_arm64_mixed_adapter
    ldp x29, x30, [sp], #16
    ret

binobf_arm64_run_indirect:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    sub sp, sp, #32
    mov x8, sp
    bl binobf_arm64_indirect_adapter
    ldp x9, x10, [sp]
    ldp x11, x12, [sp, #16]
    add x0, x9, x10
    add x0, x0, x11
    add x0, x0, x12
    mov sp, x29
    ldp x29, x30, [sp], #16
    ret

binobf_arm64_abi_target:
    mov x9, x0
    add x9, x9, x1, lsl #1
    add x9, x9, x2, lsl #2
    add x9, x9, x3, lsl #3
    add x9, x9, x4, lsl #4
    add x9, x9, x5, lsl #5
    add x9, x9, x6, lsl #6
    add x9, x9, x7, lsl #7
    ldr x10, [sp]
    add x0, x9, x10, lsl #8
    ret

binobf_arm64_mixed_target:
    fmov x9, d0
    mov x10, #0x4008
    lsl x10, x10, #48
    cmp x9, x10
    b.ne binobf_arm64_mixed_failed
    umov x9, v1.d[0]
    umov x10, v1.d[1]
    add x0, x0, x9
    add x0, x0, x10
    ret
binobf_arm64_mixed_failed:
    mov x0, #0
    ret

binobf_arm64_indirect_target:
    mov x9, #10
    mov x10, #20
    mov x11, #30
    mov x12, #40
    stp x9, x10, [x8]
    stp x11, x12, [x8, #16]
    ret

.section .rodata
binobf_arm64_pass_message:
    .asciz "ARM64_ABI_PASS\n"
binobf_arm64_integer_one_message:
    .asciz "ARM64_ABI_FAIL_INTEGER_ONE\n"
binobf_arm64_integer_two_message:
    .asciz "ARM64_ABI_FAIL_INTEGER_TWO\n"
binobf_arm64_mixed_message:
    .asciz "ARM64_ABI_FAIL_MIXED\n"
binobf_arm64_indirect_message:
    .asciz "ARM64_ABI_FAIL_INDIRECT\n"
