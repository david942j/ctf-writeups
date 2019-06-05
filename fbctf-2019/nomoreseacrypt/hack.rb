#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'gdb'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

src = <<-EOS
// Copyright 2019 - QwarkSoft
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
EOS

IO.binwrite('src.cpp', src)
IO.binwrite(File.expand_path('~/src/charmony/lib/strangefinder/splinesreticulator.cpp'), src)

gdb = GDB::GDB.new('chromeupdater')
gdb.b(0x40071a)
gdb.b(0x40071a + 5)

gdb.run
rdi = gdb.reg('rdi')
log.dump rdi.hex
gdb.continue

name = 'buildmaster'
gdb.writem(rdi + 8, name.size, as: :u64)
gdb.writem(rdi + 16, name) # hack the returned string of username to be 'buildmaster'

gdb.b(0x40089e) # mock time(NULL)'s return value
gdb.continue
gdb.execute('set $rax=1559665775')

gdb.b(0x4008f3) # call do_encrypt
gdb.b(0x4008f3 + 5) # end of call do_encrypt
gdb.continue

lala_at = gdb.reg('rdi')
plain_at = gdb.reg('rsi')
plain_len = gdb.reg('rdx')
fail if plain_len != src.size
magic_at = gdb.reg('rcx')
lala = gdb.readm(lala_at, 256)
magic = gdb.readm(magic_at, 256)

log.dump lala
log.dump magic
IO.binwrite('lala_1559665775', lala)
IO.binwrite('magic', magic)

gdb.continue
# encryption result
enc = gdb.readm(plain_at, plain_len)
log.dump enc
gdb.interact
