#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'

c151 = IO.binread('e.zip').index(IO.binread('danny.zip'))
lens = IO.binread('e.pusheen.log').lines.map(&:split).map{|c|c[1].to_i}
(72..90).each do |danny|
  guess = lens[0, c151 + danny].sum
  low = guess - 200
  up = guess + 200
  low.upto(up) do |offset|
    puts "timeout 10 ./tree #{offset} secrets.zip.enc #{danny}"
  end
end
