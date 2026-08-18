.text
.p2align 2
.space 16
.globl binobf_arm64_unwind_target
.type binobf_arm64_unwind_target, %function
binobf_arm64_unwind_target:
  nop
  .space 1024
  ret
.size binobf_arm64_unwind_target, .-binobf_arm64_unwind_target
