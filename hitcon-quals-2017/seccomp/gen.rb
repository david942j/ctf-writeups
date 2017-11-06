#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'seccomp-tools/const'
include SeccompTools::Const::BPF

srand(217217)

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

class Key
  attr_reader :main
  def initialize(main)
    fail if main.size != 16
    key = main.bytes.reverse.inject(0){ |h, c| h * 256 + c }
    @main = key
    sub = []
    54.times do |i|
      sub.push((key >> (112 - 16 * (i % 8))) & 0xffff)
      key = ((key << 25) | (key >> 103)) % (1 << 128) if i % 8 == 7
    end
    @keys = sub.each_slice(6).to_a
    @cur = 0
  end

  def get
    @cur += 1
    @keys[@cur - 1]
  end
end

def expect(val)
  @asm.puts "alu ^ X"
  @asm.puts "cmp == #{val} 1 0"
  @asm.puts 'return KILL'
end

def mul(idx, key)
  yield("ld A, mem[#{idx}]")
  yield("cmp == 0 0 1")
  yield('ld A, 0x10000')
  fail if key == 0
  yield("alu * #{key}")
  yield('misc X=A')
  yield('alu / 0x10001')
  yield('alu * 0x10001')
  # A = X - A
  yield('alu neg 0')
  yield('alu + X')
  yield('cmp == 0x10000 0 1')
  yield('ld A, 0')
  yield("st mem[#{idx}], A")
  # store back
end

def add(idx, key)
  yield("ld A, mem[#{idx}]")
  yield("alu + #{key}")
  yield("alu & 0xffff")
  yield("st mem[#{idx}], A")
end

def add_var(idx, idx2, st)
  yield("ld A, mem[#{idx}]")
  yield("ld X, mem[#{idx2}]")
  yield('alu + X')
  yield("alu & 0xffff")
  yield("st mem[#{st}], A")
end

def xor(a, b, o)
  yield("ld A, mem[#{a}]")
  yield("ld X, mem[#{b}]")
  yield("alu ^ X")
  yield("st mem[#{o}], A")
end

def ka_layer(key, &block)
  # y1 = _mul(x1, z1)
  mul(0, key[0], &block)
  # y2 = (x2 + z2) % 0x10000
  add(1, key[1], &block)
  # y3 = (x3 + z3) % 0x10000
  add(2, key[2], &block)
  # y4 = _mul(x4, z4)
  mul(3, key[3], &block)
end

def ma_layer(key, &block)
	# p = y1 ^ y3
	xor(0, 2, 4, &block) # mem[4]: p
	# q = y2 ^ y4
  xor(1, 3, 5, &block) # mem[5]: q
	# s = _mul(p, z5)
  mul(4, key[4], &block) # mem[4]: s
	# t = _mul((q + s) % 0x10000, z6)
  add_var(4, 5, 5, &block) # mem[5]: q + s
  mul(5, key[5], &block) # mem[5]: t

	# u = (s + t) % 0x10000
  add_var(4, 5, 4, &block) # mem[4]: u
	# x1 = y1 ^ t
  xor(0, 5, 0, &block)
	# x2 = y2 ^ u
  xor(1, 4, 1, &block)
	# x3 = y3 ^ t
  xor(2, 5, 2, &block)
	# x4 = y4 ^ u
  xor(3, 4, 3, &block)
end

# mem[0:4]: input
def one_round(key_obj, swap: true, &block)
  key = key_obj.get
  ka_layer(key, &block)
  ma_layer(key, &block)

  if swap
    # swap x2, x3
    yield('ld A, mem[1]')
    yield('ld X, mem[2]')
    yield('st mem[1], X')
    yield('st mem[2], A')
  end
end

def ans(key, plain)
  Integer(`./enc.py #{'%#x' % key} #{'0x' + plain.map{|c| '%02x' % c }.join}`.strip)
end

plaintext = 'w0w_y0u_are_Master-0F-secc0mp///>_w_<///'
# puts plaintext.scan(/.{8}/).map{|c|c.unpack("Q*")[0]}; exit
raise ArgumentError, plaintext.size unless plaintext.size % 8 == 0 && plaintext.size <= 48
kee = 'I_am_a_fake_flag_Come_0n_7ry_reverse_this_fxxking_seccomp_rules!'
raise ArgumentError, kee.size if kee.size % 16 != 0
keys = kee.chars.each_slice(16).to_a.map(&:join)
@asm = asm = StringIO.new
asm.puts('ld A, data[0]')
asm.puts('cmp == 0x1337 1 0')
asm.puts('return ALLOW')
plaintext.chars.each_slice(8).with_index do |plain, idx|
  plain = plain.join.unpack('S*').reverse
  fail if plain.size != 4
  fail unless plain.all? { |i| 0 <= i && i < 65536 }

  key = Key.new(keys[idx % keys.size])
  asm.puts("ld A, data[#{16 + idx * 8}]")
  asm.puts('misc X=A')
  asm.puts("alu & 0xffff")
  asm.puts("st mem[3], A")
  asm.puts('misc A=X')
  asm.puts('alu >> 16')
  asm.puts("st mem[2], A")
  asm.puts("ld A, data[#{16 + idx * 8 + 4}]")
  asm.puts('misc X=A')
  asm.puts("alu & 0xffff")
  asm.puts("st mem[1], A")
  asm.puts('misc A=X')
  asm.puts('alu >> 16')
  asm.puts("st mem[0], A")
  8.times { |i| one_round(key, swap: i != 7) { |a| asm.puts(a) } }
  ka_layer(key.get) { |a| asm.puts(a) }
  tar = ans(key.main, plain)

  asm.puts("ld X, 0x1337") # additional xor key
  3.downto(0) do |i|
    asm.puts("ld A, mem[#{i}]")
    expect(0x1337 ^ (tar & 0xffff))
    tar >>= 16
  end
end

dis = Disasm.new

asm.puts 'return ALLOW' # prevent not end with return
asm.string.lines.reverse.each { |l| dis.prepend(l) }
print dis.result
