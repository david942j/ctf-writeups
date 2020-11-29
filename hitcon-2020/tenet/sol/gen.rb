#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'pwn'        # https://github.com/peter50216/pwntools-ruby

context.arch = :amd64

cookie_at = 0x2170000
sc = asm(<<-EOS)
mov rdx, #{cookie_at}
mov rax, qword ptr [rdx]
xor rcx, rcx
mov qword ptr [rdx], rcx
mov rdx, #{cookie_at}
mov rbp, 64
loop:
  test rbp, rbp
  jz out
  dec rbp
  shr rax, 1
  jc one
  jmp zero
one:
  bts rcx, 0
  shl rcx, 1
  jmp loop
zero:
  shl rcx, 1
  jmp loop

out:
xor rax, rax
mov al, 60
syscall
EOS
$stderr.puts disasm(sc)
puts sc.size
print sc
