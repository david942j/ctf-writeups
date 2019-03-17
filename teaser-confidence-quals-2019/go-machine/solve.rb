#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo

# @magic = one_gadget(file: './libc.so.6')[0]
#================= Exploit Start ====================
# context.arch = :amd64
# debug!

def string_at(addr, len)
  addr -= 0x400000 if addr >= 0x400000
  File.open('go-machine') do |f|
    f.pos = addr
    f.read(len)
  end
end

def command
  @command ||= string_at(0x4be653, 0x32abe)
end

def ary
  @ary ||= string_at(0x4FDC10, 16)
end

class Lambda
  attr_accessor :v1, :op, :v2
  attr_accessor :type

  def initialize(obj)
    @op = nil
    case obj
    when Integer
      type = :int
      @v1 = obj
    when String
      type = :var
      @v1 = obj
    when Lambda
      type = :obj
      @v1 = obj
    else
      fail
    end
  end

  def coerce(other)
    [self, other]
  end

  def integer?
    op == :nil && type == :int
  end

  %i[+ - * % <<].each do |sym|
    define_method(sym) do |other|
      if integer? && other.integer?
        return Lambda.new(v1.__send__(sym, other.v1))
      end

      if op == :nil
        v = Lambda.new(v1)
      else
        v = Lambda.new(self)
      end

      v.op = sym
      v.v2 = other
      return v
    end
  end

  def to_s
    if op == nil
      return v1.to_s
    end

    case type
    when :int then v1.hex
    when :var then v1.inspect
    else
      v2_s = v2.hex
      if v2.integer?
        if v2_s == '0x88ca6b51'
          v2_s = 'N'
        end
      end
      ret = "(#{v1} #{op} #{v2_s})"
      ret = 'B' if ret == '(((v0 << 0x18) + ((v1 << 0x10) + ((v2 << 0x8) + v3))) * 0x1)'
      ret
    end 
  end
  alias hex to_s
end

class Ctx
  attr_accessor :pc, :seed, :stack, :mm

  def initialize
    @pc = 0
    @seed = 0
    @stack = []
    @mm = Array.new(99) { 0 }
  end

  def process
    case command[@pc]
    when ary[0]
      op(:-, 4)
    when ary[1]
      op(:+, 10)
    when ary[2]
      stack[-1] = stack[-1] * -1
    when ary[3]
      op(:*, 25)
    when ary[4]
      op(:%, 7)
    when ary[5]
      push(command[@pc+1, 20].to_i); s 13
      @pc += 20
    when ary[6]
      stack.pop
    when ary[7]
      read
    when ary[8]
      p stack[-1] # (?)
    when ary[9]
      push(stack[-1])
    when ary[10]
      mm[command[@pc+1, 2].to_i] = stack[-1]
      @pc += 2
    when ary[11]
      stack[-1] = mm[command[@pc+1, 2].to_i]
      @pc += 2
    when ary[12]
      stack[-2] = stack[-1]; stack.pop
    when ary[13]
      op(:<<, 0)
    when ary[14]
      check!
    when ary[15]
      swap!
    else
    end
    @pc += 1
  end

  private

  def swap!
    g = seed
    15.downto(1) do |j|
      g = (0x19660D * g + 0x3C6EF35F) % (2**32);
      val = g % j;
      org = ary[j];
      ary[j] = ary[val];
      ary[val] = org;
    end
  end

  def check!
    puts "Expect #{stack[-1]} to be #{stack[-2].hex}"
  end

  def read
    @var_cnt ||= 0
    push(Lambda.new("v#{@var_cnt}"))
    @var_cnt += 1
  end

  def push(val)
    # p "push #{val}"
    stack.push(val)
  end

  def op(sym, inc)
    if sym == :<< && stack[-1] >= 64
      stack[-2] = 0
    else
      stack[-2] = stack[-2].__send__(sym, stack[-1])
      # stack[-2] %= 2**64
    end
    stack.pop
    s inc
  end

  def s(v)
    @seed += v
  end
end

def simulate
  @ctx = Ctx.new

  while @ctx.pc <= command.size
    @ctx.process
  end
end

simulate

# [0123]**257 % 0x88ca6b51 == 0xf2227a5
# [4567]**257 % 0x8405b751 == 0x4e053304
# [89ab]**257 % 0xbfa08c87 == 0x706fc204
# [cdef]**257 % 0x82013f23 == 0x4283b66c
# [ghij]**257 % 0x4666751b == 0x1e5cc83a
# [ghij]**257 % 0x5271083f == 0x1faf011c
