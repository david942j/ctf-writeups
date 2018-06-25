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

if args.REMOTE:
    r = remote("35.233.98.21", 4242)
else:
    r = remote("mlwr-part1.ctfcompetition.com", 1234)


data = 'part1 flag\0'
p = p32(8 + len(data) + 1) + key + data
p += chr(checksum(key + data))

r.send(p)

r.interactive()
# CTF{I don't always encrypt my strings, but when I do, I inline them all}
