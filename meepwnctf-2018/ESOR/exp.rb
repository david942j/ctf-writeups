#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '206.189.92.209', 12345
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

def enc(prefix='',suffix='')
  z.gets 'quit'
  z.puts 1
  # z.gets 'prefix'
  z.puts prefix
  z.gets 'suffix: '
  z.puts suffix
  z.gets.strip.unhex
end

def dec(data)
  # z.gets 'quit'
  z.puts 2
  z.gets 'data: '
  z.puts data.enhex
  z.gets.strip == 'OK'
end
flag_len = 48
# |------------------|enc(flag)|

def solve(base, off)
  valid = enc('A' * 12)[0, 96]
  0.step do |i|
    print '.'
    e = enc('A' * off)
    if dec(valid + e[base, 16])
      return (valid[-1].ord ^ e[base-1].ord ^ 15).chr
    end
  end
end

ii = ARGV[0].to_i # 0~47
off = 15 - ii % 16
base = (ii / 16 + 1) * 16
c = solve(base, off)
p c

flag = 'MeePwnCTF{pooDL3' + '-this-is-la-vie-' + 'en-rose-P00dle!}'
puts flag
