#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]
#================= Exploit Start ====================
# context.log_level = :debug
def fetch(die = true)
  @z = Sock.new '202.120.7.211', 8719
  @z.recvn(34848)
ensure
  @z.close if die
end

def collect
  cc = {}
  12.times do |j|
    fetch.lines.each_with_index do |l, i|
      cc[i] ||= {}
      cc[i][l] ||= 0
      cc[i][l] += 1
    end
    log.info("======= #{j + 1} =======")
  end
  cc.map do |(i, e)|
    # p e.min_by { |(k, v)| k.size }.last
    [i, e.min_by { |(k, v)| k.size }.first]
  end.to_h
end

def work(cc)
  flag =''
  fetch(false).lines.each_with_index do |l, i|
    next if cc[i] == l
    flag << l.chars.zip(cc[i].chars).find { |a,b| a!=b }[0]
    p flag
  end
  @z.puts flag
  @z.interact
end
work(collect)

# flag{h1dden_7cp_m5g_lol}
