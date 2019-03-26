#!/usr/bin/env ruby
# encoding: ascii-8bit
# require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
# require 'heapinfo'   # https://github.com/david942j/heapinfo
# require 'one_gadget' # https://github.com/david942j/one_gadget

poly = 0xb595cf9c8d708e2166d545cf7cfdd4f9
# 0x9f2bbf3ef3a2ab6684710eb139f3a9ad
# poly = 0xEDB88320

tbl = []
b = 0
loop do
  remainder = b
  8.times do
    if (remainder & 1) == 1
      remainder = (remainder >> 1) ^ poly;
    else
      remainder = (remainder >> 1);
    end
  end
  tbl[b] = remainder
  b+=1
  break if b == 256
end

# puts tbl.map(&:hex)

n = 128
# n = 32
res = 2**n - 1
input = 'flag{0123456789abcdef}'
# input = 'flag{0123456789abcdef}'
# input = '0123456789abcdef'
# input = 'a' * 32
# input = '123'
input.bytes.each do |i|
  res = (res >> 8) ^ tbl[(res ^ i) & 0xff]
end

p '0x' + res.to_s(16)
# flag{670344c379b7f7fa4555a50fbabaefa4}
