.text
.p2align 2
.globl binobf_arm64_windows_unwind_reference
.def binobf_arm64_windows_unwind_reference
.scl 2
.type 32
.endef
.seh_proc binobf_arm64_windows_unwind_reference
binobf_arm64_windows_unwind_reference:
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    mov x29, sp
    .seh_set_fp
    sub sp, sp, #80
    .seh_stackalloc 80
    .seh_endprologue
    mov sp, x29
    .seh_startepilogue
    .seh_set_fp
    ldp x29, x30, [sp], #16
    .seh_save_fplr_x 16
    ret
    .seh_endepilogue
    .seh_endproc
