#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

#================= Exploit Start ====================

@map = <<-EOS.lines.map(&:chars)
00000000203211000
00000001034230E00
00000010221301000
00000002010000000
00000000S00000000
00000000000000000
00000000000000000
00000000000000000
00000000000000000
EOS

@ans = []
@dx = [-1, -1,  1,  1]
@dy = [-1,  1, -1,  1]

def ok(ans)
  return true if ans.size % 4 != 0

  res = ans.each_slice(4).map do |l|
    '%02x' % l.map { |c| '%02b' % c }.reverse.join.to_i(2)
  end.join.unhex
  res.match?(/\A[\w{}]+\Z/) && res[0] == 'p' && res[1] == '4' && res[2] == '{'
end

def out(ans)
  fail if ans.size != 36
  res = ans.each_slice(4).map do |l|
    '%02x' % l.map { |c| '%02b' % c }.reverse.join.to_i(2)
  end.join.unhex
  return unless res.end_with?('}')
  p res
end

def go(x, y, step)
  return if @ans.size >= 12 && !ok(@ans)

  4.times do |d|
    a = x + @dx[d]
    b = y + @dy[d]
    a = x if a < 0 || a >= @map.size
    b = y if b < 0 || b >= @map[0].size
    next if ['0', "\n", 'S'].include?(@map[a][b])

    if @map[a][b] == 'E'
      @ans << d
      (out(@ans)) if step == 0
      @ans.pop
      next
    end
    @ans << d
    @map[a][b] = (@map[a][b].to_i - 1).to_s
    go(a, b, step - 1)
    @map[a][b] = (@map[a][b].to_i + 1).to_s
    @ans.pop
  end
end

go(4, 8, 35)
