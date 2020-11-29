#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'pwn'
require 'seccomp-tools'

context.arch = :amd64

res = ::SeccompTools::Asm.asm(<<-EOS, arch: :amd64)
  A = arch
  A == ARCH_X86_64 ? next : dead
  A = sys_number
  A == munmap ? ok : dead
dead:
  return KILL
ok:
  return ALLOW
EOS

# ::SeccompTools::Util.template('asm.amd64.asm').sub(
#   '<TO_BE_REPLACED>',
#   res.bytes.map { |b| format('\\\%03o', b) }.join
# )

sc = asm(<<-EOS)
jmp unmap_stk
install_seccomp:
  push   38
  pop    rdi
  push   0x1
  pop    rsi
  xor    eax, eax
  mov    al, 0x9d
  syscall
  push   22
  pop    rdi
  lea    rdx, [rip + _filter]
  push   rdx /* .filter */
  push   _filter_end - _filter >> 3 /* .len */
  mov    rdx, rsp
  push   0x2
  pop    rsi
  xor    eax, eax
  mov    al, 0x9d
  syscall
  add rsp, 16 /* restore the two pushes */
  ret
_filter:
  .ascii "#{res.bytes.map { |b| format('\\%03o', b) }.join}"
_filter_end:
unmap_stk:
  call install_seccomp
  mov     rdi, rsp
  and     rdi, 0xfffffffffffff000
  sub     rdi, 0x21000
  mov     rsi, 0x24000
  xor     rax, rax
  mov     al, 0xb
  syscall
EOS

p sc, sc.size
# puts disasm(sc)
