.globl panic
.extern hlt
.intel_syntax noprefix
panic:
  mov eax, edi
  mov dx, 0xffff
  out dx, eax
  jmp hlt
