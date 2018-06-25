#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'memory_io'
require 'gdb'

host, port = 'keygenme.ctfcompetition.com', 1337
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
#================= Exploit Start ====================
# context.log_level = :debug

def rev(target)
  res = Array(32)
  16.times do |i|
    a = target[i].ord ^ i ^ (16 * i)
    res[2*i+1] = a & 0xf
    res[2*(15-i)] = a >> 4
  end
  res.map{|c|c.to_s(16)}.join
end
def gdb
  return @gdb if @gdb
  @gdb = GDB::GDB.new('-nx keygenme').tap { |g| g.b(0x00007ffff7fddc62) }
end

def solve(name)
  k = Tubes::Process.new('./keygenme')
  # gdb.interact
  gdb.exec('attach ' + `pidof keygenme`.strip.split.last)
  k.puts(name + 'a' * 32)
  gdb.exec('c')
  gdb.exec('c 62')
  # gdb.interact
  target = MemoryIO::Process.new(`pidof #{name}`.to_i).read('stack+0x20f00-0x2d0+0x20+64', 32).unhex
  gdb.exec('detach')
  k.close
  rev(target)
end

$z = Sock.new host, port
def z;$z;end
1.step do |i|
  p i
  name = z.gets.strip
  p name
  ans = solve(name)
  p ans
  z.puts ans
  p z.gets
end

z.interact

# CTF{g1mm3_A11_T3h_keyZ}
