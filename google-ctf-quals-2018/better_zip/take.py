import os
import zipfile
import zlib
import hashlib
from struct import pack, unpack
import sys

POLY_SZ = 20
poly_sz = 20


class BitStream:
  def __init__(self, data, sz=None):
    if sz is None:
      sz = len(data) * 8

    self.sz = sz
    self.data = bytearray(data)
    self.idx = 0

  def get_bit(self):
    if self.idx >= self.sz:
      raise Exception('All bits used. Go away.')

    i_byte = self.idx / 8
    i_bit = self.idx % 8

    bit = (self.data[i_byte] >> i_bit) & 1
    self.idx += 1

    return bit

  def get_bits(self, sz):
    v = 0
    for i in xrange(sz):
      v |= self.get_bit() << i

    return v


class LFSR:
  def __init__(self, poly, iv, sz):
    self.sz = sz
    self.poly = poly
    self.r = iv
    self.mask = (1 << sz) - 1

  def get_bit(self):
    bit = (self.r >> (self.sz - 1)) & 1

    new_bit = 1
    masked = self.r & self.poly
    for i in xrange(self.sz):
      new_bit ^= (masked >> i) & 1

    self.r = ((self.r << 1) | new_bit) & self.mask
    return bit


class LFSRCipher:
  def __init__(self, key, poly_sz=8, key_iv=None, cipher_iv=None):
    if len(key) < poly_sz:
      raise Exception('LFSRCipher key length must be at least %i' % poly_sz)
    key = BitStream(key)

    if key_iv is None:
      key_iv = os.urandom(poly_sz)
    self.key_iv = key_iv
    key_iv_stream = BitStream(key_iv)

    if cipher_iv is None:
      cipher_iv = os.urandom(poly_sz)
    self.cipher_iv = cipher_iv
    cipher_iv_stream = BitStream(cipher_iv)

    self.lfsr = []
    for i in xrange(8):
      l = LFSR(key.get_bits(poly_sz) ^ key_iv_stream.get_bits(poly_sz),
               cipher_iv_stream.get_bits(poly_sz), poly_sz)
      self.lfsr.append(l)

  def get_keystream_byte(self):
    b = 0
    for i, l in enumerate(self.lfsr):
      b |= l.get_bit() << i
    return b

  def get_headers(self):
    return self.key_iv + self.cipher_iv

  def crypt(self, s):
    s = bytearray(s)
    for i in xrange(len(s)):
      s[i] ^= self.get_keystream_byte()
    return str(s)


# A super short ZIP implementation.
def SETBIT(n):
  return 1 << n

def db(v):
  return pack("<B", v)

def dw(v):
  return pack("<H", v)

def dd(v):
  return pack("<I", v)

import zlib

def mp32(x):
  return dd(x)[::-1]

fname = 'flag.zip'
name = 'flag.png'
data = open(fname, 'rb').read()
data = data[0x26:]

key_iv = data[:20]
cipher_iv = data[20:40]

data = data[40:]

size = 0x16dea
enc_data = data[:size]

key_iv_stream = BitStream(key_iv)
cipher_iv_stream = BitStream(cipher_iv)
key_ivs = [ key_iv_stream.get_bits(poly_sz) for i in xrange(8)]
cipher_ivs = [ cipher_iv_stream.get_bits(poly_sz) for i in xrange(8)]
#print key_ivs
#print cipher_ivs
bitnum = 20

idx = 1

prefix = 'IHDR\x00\x00\x02\x80'
#  maybe1 = ['\x00\x00','\x00\x00']
maybe2 = ['\x08\x06','\x08\x04','\x08\x02', '\x08\x00']

#chunk = prefix + maybe1[1] + maybe2[2]+'\x00\x00\x00'
#crc = zlib.crc32(chunk)&0xffffffff
known1 = '\x00\x00'
known2 = maybe2[2]+'\x00\x00\x00'
maybe3 = ['PLTE','IDAT', 'gAMA', 'sRGB', 'tIME']
known3 = '\x00\x00'
known4 = maybe3[3]
known5 = maybe3[2]

"""
c = LFSRCipher('\x00'*20,POLY_SZ,key_iv,cipher_iv)
dd = c.crypt(enc_data[:20])
print dd
exit()
"""
for idx in range(1, 8):
  k_candi = []
  for k in xrange(1<<20):
    if k%100000 == 0: 
      print k
      print idx,len(k_candi)
    lfsr = LFSR(k ^ key_ivs[idx], cipher_ivs[idx], poly_sz)
    bits = [ lfsr.get_bit() for i in xrange(56)]
    ok = True
    for i in xrange(len(known1)):
      index = 20+i
      bit = ( (ord(known1[i]) ^ ord(enc_data[index]) ) >> idx ) & 1
      if bit != bits[index]:
        ok = False
    for i in xrange(len(known2)):
      index = 24+i
      bit = ( (ord(known2[i]) ^ ord(enc_data[index]) ) >> idx ) & 1
      if bit != bits[index]:
        ok = False
    for i in xrange(len(known3)):
      index = 33+i
      bit = ( (ord(known3[i]) ^ ord(enc_data[index]) ) >> idx ) & 1
      if bit != bits[index]:
        ok = False
    #  for i in xrange(len(known4)):
      #  index = 37+i
      #  bit = ( (ord(known4[i]) ^ ord(enc_data[index]) ) >> idx ) & 1
      #  if bit != bits[index]:
        #  ok = False
    for i in xrange(len(known5)):
      index = 50+i
      bit = ( (ord(known5[i]) ^ ord(enc_data[index]) ) >> idx ) & 1
      if bit != bits[index]:
        ok = False
    if ok: k_candi.append(k)

  print k_candi
  print len(k_candi)
  plain = '\x00\x00\x00\x00IEND\xae\x42\x60\x82'
  k_candi1 = []
  for k in k_candi:
    lfsr = LFSR(k ^ key_ivs[idx], cipher_ivs[idx], poly_sz)
    bits = [ lfsr.get_bit() for i in xrange(size)]
    ok = True
    for i in xrange(12):
      index = size-12+i
      bit = ( (ord(plain[i]) ^ ord(enc_data[index]) ) >> idx ) & 1
      if bit != bits[index]:
        ok = False
    if ok: k_candi1.append(k)

  print k_candi1
  print len(k_candi1)
  if len(k_candi1) == 0: break

