#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'pwn'        # https://github.com/peter50216/ruby-pwntools
code = {}
mapping = []
IO.binread('cute_v8.parsed').lines.map.with_index do |line, i|
  l, inst = line.strip.split(':')
  l = l.to_i
  inst = inst.strip.split(';')[0].split(' ').map{|c|c.gsub(',','')}
  code[l] = inst
  mapping << l
end
# p code
class C
  attr_accessor *%i[a r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12]
end
@con = C.new
def push(c)
  @flag ||= ''
  @flag += c.chr
  p @flag
  @con.a = 1
end

def r(s)
  @con.send(s.to_sym)
end

def re(s, val)
  @con.send((s+'=').to_sym, val)
end
pc = 0
loop do
  inst = code[mapping[pc]]
  pc += 1
  case inst[0]
  when 'StackCheck', 'Nop'; next
  when 'LdaSmi'; @con.a = inst[1][1..-2].to_i
  when 'Star'; @con.send((inst[1] + '=').to_sym, @con.a)
  when 'LdaConstant'; next
  when 'LdaZero'; @con.a = 0
  when 'LdaGlobal'; fail if inst[1] != '[1]'
  when 'LdaNamedProperty'; fail if inst[2] != '[2]'
  when 'CallProperty1'; push(@con.send(inst[3].to_sym))
  when 'Add'; @con.a += @con.send(inst[1].to_sym) 
  when 'AddSmi'; @con.a += inst[1][1..-2].to_i
  when 'Mov'; re(inst[1], r(inst[2]))
  when 'Inc'; @con.a += 1
  when 'TestLessThanOrEqual'; @con.a = (r(inst[1]) <= @con.a ? 1 : 0)
  when 'TestGreaterThanOrEqual'; @con.a = (r(inst[1]) >= @con.a ? 1 : 0)
  when 'TestLessThan'; @con.a = (r(inst[1]) < @con.a ? 1 : 0)
  when 'TestEqual'; @con.a = (r(inst[1]) == @con.a ? 1 : 0)
  when 'JumpIfFalse'
    pc = mapping.index(inst.last.to_i) if @con.a == 0
  when 'JumpIfTrue'
    pc = mapping.index(inst.last.to_i) if @con.a == 1
  when 'JumpLoop'
    pc = mapping.index(inst.last.to_i)
  when 'Ldar'; @con.a = r(inst[1])
  when 'BitwiseXorSmi'; @con.a ^= inst[1][1..-2].to_i
  else (p inst; fail)
  end
end
