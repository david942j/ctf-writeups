#!/usr/bin/env python2

from __future__ import print_function
from pwn import *
import gmpy, string

e = 257
for p,q,c in [
        [9227, 248723, 0xf2227a5],
        [22433, 98737, 0x4e053304],
        [4547, 707053, 0x706fc204],
        [107, 20384297, 0x4283b66c],
        [13, 90855367, 0x1e5cc83a],
        [277, 4993283, 0x1faf011c],
]:
    n = p * q
    r = (p-1)*(q-1)
    d = gmpy.invert(e, r)
    ans = pow(c, d, n)
    while not all(map(lambda x: x in string.printable, p32(ans))):
        ans += n
    print(p32(ans, endian='big'), end='')
