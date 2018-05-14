#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

s = IO.binread('mcalc')
context.arch = :amd64
s[0x15d4, 8] = asm('nop') * 3 + asm("mov edx, 0xABC8EEF")
s[0x15ef, 8] = asm('nop') * 3 + asm("mov edx, 0xB096BFF4")
s[0x160b, 8] = asm('nop') * 3 + asm("mov edx, 0xE0C54799")
s[0x1627, 8] = asm('nop') * 3 + asm("mov edx, 0x68CBC732")
# s[s.index('strlen'), 5] = "free\x00"

# s[s.index('/lib64/ld'), 9] = './ib64-ld'
# s[s.index('libc.so.6'), 2] = './'
# s[0x30a0, 2] = "Me"
IO.binwrite('mcalc.patch', s)
