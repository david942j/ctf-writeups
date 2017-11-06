#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'seccomp-tools/const'
include SeccompTools::Const::BPF

class Disasm
  attr_reader :insts
  def initialize
    @insts = []
  end

  def prepend(line)
    insts.unshift(
      case line
      when /^return/ then ret(line.split.last)
      when /^ld / then ld(src_of(line), dst_of(line))
      when /^st / then st(src_of(line), dst_of(line))
      when /^cmp / then cmp(line)
      when /^alu / then alu(line.split[1], dst_of(line))
      when /^misc / then misc(line)
      else fail(line)
      end
    )
  end

  def result
    insts.map do |inst|
      [inst[:op]].pack('S') + [inst[:jt] || 0, inst[:jf] || 0].pack('C*') + [inst[:k] || 0].pack('L')
    end.join
  end

  private

  def st(mem, reg)
    fail if mem[0] != :mem
    cmd = case reg
          when :a then COMMAND[:st]
          when :x then COMMAND[:stx]
          else fail(reg)
          end
    { op: cmd, k: mem[1] }
  end

  def ld(reg, val)
    cmd = case reg
          when :a then COMMAND[:ld]
          when :x then COMMAND[:ldx]
          else fail(reg)
          end
    k = case val
        when Integer then val
        when Array then val[1]
        else fail(val)
        end
    cmd |= MODE[:imm] if val.is_a?(Integer)
    if val.is_a?(Array)
      cmd |= case val[0]
             when :mem then MODE[:mem]
             when :data then MODE[:abs]
             else fail(val)
             end
    end
    { op: cmd, k: k }
  end

  def src_of(l)
    obj_of(l.split(',')[0].split.last)
  end

  def dst_of(l)
    obj_of(l.split(',')[-1].split.last)
  end

  def obj_of(v)
    # A
    # mem[10]
    case v
    when 'A' then :a
    when 'X' then :x
    when /mem\[\d+\]/ then [:mem, Integer(v.scan(/\d+/)[0])]
    when /data\[\d+\]/ then [:data, Integer(v.scan(/\d+/)[0])]
    else Integer(v)
    end
  end

  def misc(line)
    case line
    when /X=A/ then { op: COMMAND[:misc] | MISCOP[:tax] }
    when /A=X/ then { op: COMMAND[:misc] | MISCOP[:txa] }
    else fail(line)
    end
  end

  def alu(op, val)
    type = case op
           when '*' then :mul
           when '+' then :add
           when '-' then :sub
           when '/' then :div
           when '|' then :or
           when '&' then :and
           when '^' then :xor
           when 'neg' then :neg
           when '>>' then :rsh
           else fail(op)
           end
    op = COMMAND[:alu] | OP[type]
    k = val == :x ? 0 : val #######
    if val == :x
      k = rand(0..65535)
      op |= SRC[:x]
    else k = val
    end
    { op: op, k: k }
  end

  def ret(kind)
    type = {
      'ALLOW' => 0x7fff0000,
      'ERRNO' => 0x00050001,
      'KILL' => 0
    }[kind]
    raise ArgumentError, kind if type.nil?
    { op: COMMAND[:ret], k: type }
  end

  def cmp(line)
    _, op, k, jt, jf = line.strip.split
    code = COMMAND[:jmp]
    if k == 'X'
      code |= SRC[:x]
      k = 0
    else
      k = Integer(k)
    end
    jt = Integer(jt)
    jf = Integer(jf)
    type = case op
           when '==' then :jeq
           when '>' then :jgt
           when '>=' then :jge
           when '&' then :jset
           else fail(op)
           end
    { op: code | JMP[type],  k: k, jt: jt, jf: jf}
  end
end

def expect(val)
  @asm.puts "alu ^ X"
  @asm.puts "cmp == #{val} 1 0"
  @asm.puts 'return KILL'
end

dis = Disasm.new
asm = @asm = StringIO.new
def c(s); @asm.puts(s); end
c 'ld A, data[0]'
c 'cmp == 231 0 1'
c 'return ALLOW'
c 'cmp >= 200 0 1'
c 'return ERRNO'
[2, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 53, 56, 57, 58, 62, 101, 157].each do |v|
  c "cmp == #{v} 0 1"
  c 'return ERRNO'
end

asm.puts 'return ALLOW' # prevent not end with return
asm.string.lines.reverse.each { |l| dis.prepend(l) }
puts dis.result.bytes.join(', ')
# print dis.result
