#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

f = 'X' * 28
{
  '}' => 27,
  '_' => 19849,
  'u' => 25,
  't' => 5,
  's' => 11,
  'n' => 8,
  'l' => 486,
  'k' => 643,
  'i' => 16,
  'h' => 786,
  'e' => 21,
  'c' => 23,
  '7' => 22,
  '5' => 17,
  '1' => 327,
  '0' => 452,
  '{' => 2,
  '4' => 1,
  'p' => 27040
}.each do |k, v|
  while v > 0
    f[v % 32] = k
    v /= 32
  end
end
puts f

# p4{k0tl1n_1s_p0li5h_ke7chup}
