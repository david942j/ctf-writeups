#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'gdb'        # https://github.com/david942j/gdb-ruby

dec = IO.binread('flag.enc').strip.unhex
IO.binwrite('test', dec)

gdb = GDB::GDB.new('true_origin')
base = 0x555555554000
gdb.b(base + 0x152a) # 1
# gdb.b(0x35fb + base)
# gdb.b(0x315b + base) # 2
gdb.run('test')
key = gdb.readm(gdb.reg('rsi'), 40)
log.dump key
gdb.writem(gdb.reg('rsi'), key[20, 20])
gdb.writem(gdb.reg('rsi') + 20, key[0, 20])
# gdb.interact

puts gdb.continue

# ASIS{65e05d26ea3f3a2518e29fa77744f2b0}
