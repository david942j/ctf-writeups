#!/usr/bin/env python2

import gmpy
from pwn import *
n = 1408906108648127120822775586604952148832266454357812435140055286169381709951576947121
p = 1184768967212473512123668136883340418843347 
q = 1189182150814604694726460475579427891025643
e = 65537
assert n == p * q

r = (p-1) * (q-1)
d = gmpy.invert(e,  r)

plain = 12345
assert pow(pow(plain, e, n), d, n) == plain

ary = [149, 127, 168, 106, 108, 204, 18, 138, 104, 46, 127, 243, 16, 217, 250, 242, 168, 166, 95, 213, 238, 196, 69, None, 181, 116, 219, 18, 3, 168, 134, 54, 130, 30, 252]
for i in range(256):
    ary[23] = i
    v = 1
    s = 0
    for c in range(len(ary)):
        s = s * 256 + ary[c]
    t = (hex(pow(s, d, n))[2:])
    if len(t) % 2 == 1:
        t = '0' + t
    print(repr(t.decode('hex')))
# ASIS{RsA_1s_Aw3s0m3_AnD_S0_1s_V3X!}
