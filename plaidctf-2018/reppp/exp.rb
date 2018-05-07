#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'pppr.chal.pwning.xxx', 3444
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
# context.arch = 'amd64' 
# context.log_level = :debug
z.gets
z.puts 'y'
T = z.gets.to_i
T.times do |_|
  n,m,p = z.gets.split.map(&:to_i)
  fail if n == 0
  ar = Array.new(p*2+m){z.gets}
  File.open('input', 'w') do |f|
    f.puts "#{n} #{m} #{p}"
    f.puts ar
  end
  ans = `./solve < input`.strip
  p _, ans
  z.puts ans
end
z.interact
# PCTF{m1nc0st_b1p4rt1t3_m4tch1ng}
