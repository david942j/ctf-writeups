#!/usr/bin/env ruby
# encoding: ascii-8bit

d = IO.binread('fakefs.cpio.gz')

tpl = IO.binread('hack.dts.tpl')
tpl.sub!('<REPLACE>', d.bytes.map { |c| '\\x%02x' % c }.join)
IO.binwrite('hack.dts', tpl)
