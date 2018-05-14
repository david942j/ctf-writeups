#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'gdb'

gdb = GDB::GDB.new('-nh mcalc')
gdb.execute('target remote 127.0.0.1:9919')
# gdb.b(0x401ab6)
# gdb.execute('c')
# gdb.execute('x/3gx $rdi')
# gdb.interact
gdb.execute('c')
# rdi | 0x7fffffffea20
# rsp | 0x7fffffffe9b0
# r11 | 0x000000000000
# rbp | 0x7fffffffe9e0
# r13 | 0x7fffffffeca0
gdb.execute('set $rdi=0xdeadbeeffaceb00c')
# gdb.execute('set $rsp=0x7fffffffe9b0')
gdb.execute('set $r13=0x400720')
# gdb.execute('set $rbp=0x7fffffffe9e0')
# gdb.execute('set $r13=0x400720')
# gdb.execute('set $rcx=0x7fffffffe9b8')
gdb.execute('info all-registers')
gdb.writem(0x7fffffffe9b0, 'A' * 8)
# p gdb.execute('x/gx 0x7fffffffe9b0')
# # gdb.execute('x/gx 0x400720')
gdb.interact
