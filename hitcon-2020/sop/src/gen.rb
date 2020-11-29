#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'seccomp-tools'

context.arch = :amd64

SYS = SeccompTools::Const::Syscall::AMD64
PR_GET_TID_ADDRESS = 40
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SIGSYS = 31
PR_SET_NAME = 15
PR_GET_NAME = 16

class Parameter
  attr_reader :val

  def initialize(val)
    @val = val
  end

  def to_b
    [[2, 2]]
  end
end

class Immi < Parameter
  def to_b
    ret = [[2, 2]]
    s = @val.to_s(2)
    ret << [5, s.size - 1]
    ret << [s.size, @val]
    ret
  end
end

class Reg < Parameter
  def to_b
    [[2, 0], [4, @val]]
  end
end

class RegRef < Parameter
  def to_b
    [[2, 1], [4, @val]]
  end
end

class BitStream
  def initialize
    @val = 0
    @now = 0
  end

  def <<((bn, val))
    val &= (1 << bn) - 1
    @val |= val << @now
    @now += bn
    fail if @now >= 64
  end

  def to_i
    @val
  end
end

@rip = 0
def emit(nr, *params)
  @output ||= File.open('sop_bytecode', 'wb')
  bs = BitStream.new
  bs << [8, nr]
  params.each { |pa| pa.to_b.each { |b| bs << b } }
  bs << [2, 3]
  @rip += 1
  @output << bs.to_i.p64
end

def scall(nr, *args)
  emit(SYS[nr], *args.map { |v| v.is_a?(Parameter) ? v : Immi.new(v) })
end

# regs[idx] = val
def set_reg(idx, val)
  scall(:set_tid_address, val)
  scall(:prctl, PR_GET_TID_ADDRESS, RegRef.new(idx))
end

# regs[idx] = *addr
# XXX: it's actually strncpy(&regs[idx], addr, 16)
# XXX: this might screw up regs[idx + 1]
def load_reg(idx, addr)
  scall(:prctl, PR_SET_NAME, addr)
  scall(:prctl, PR_GET_NAME, RegRef.new(idx))
end

def load_reg32(idx, addr)
  load_reg(idx, addr)
  set_reg(0, 0xffffffff)
  alu32to(:&, Reg.new(0), Reg.new(idx), idx, clr_high: true)
end

srand(333)
# val must be 32-bit
def put_val(val, addr)
  idx = rand(14) # 0~13
  set_reg(idx, addr)
  scall(:set_tid_address, val)
  scall(:prctl, PR_GET_TID_ADDRESS, Reg.new(idx))
end

def sigaction_handler
  @sigaction_handler ||= asm(<<-EOS).ljust(36, "\xcc")
label:
  movabs rcx, #{0x3f8495f5793a342c}
  mov edx, dword ptr [rsi+4]
  mov word ptr [rcx], dx
  // increase the address by 2..
  lea rcx, [rip + label + 2]
  inc qword ptr [rcx]
  inc qword ptr [rcx]
  ret
  EOS
end

def restorer
  asm(<<-EOS).ljust(8, "\xcc")
  xor eax,eax
  mov al,0xf
  syscall
  EOS
end
MEM = 0x217000
INPUT_AT = MEM
INPUT_SIZE = 32
SIGACTION_AT = INPUT_AT + INPUT_SIZE
RESTORER_AT = SIGACTION_AT + sigaction_handler.size
# discard-after-use buffer
BUFFER_AT = (RESTORER_AT + restorer.size + 7) / 8 * 8

def install_sigaction
  # struct sigaction {
  #   void *action;
  #   unsigned long sa_flags;
  #   void *sa_restorer;
  #   unsigned long sa_mask;
  # } action = {
  #   .action = handler,
  #   .sa_flags = 0x4000004, // SA_RESTORER | SA_SIGINFO,
  #   .sa_restorer = restorer,
  #   .sa_mask = 0,
  # };
  [SIGACTION_AT, 0x4000004, RESTORER_AT, 0].each_with_index do |v, i|
    put_val(v, BUFFER_AT + i * 8)
    put_val(0, BUFFER_AT + i * 8 + 4)
  end
  sigaction_handler.unpack("L*").each_with_index do |v, i|
    put_val(v, SIGACTION_AT + i * 4)
  end
  restorer.unpack("L*").each_with_index do |v, i|
    put_val(v, RESTORER_AT + i * 4)
  end
  set_reg(0, BUFFER_AT)
  scall(:rt_sigaction, SIGSYS, Reg.new(0), 0, 8)
end

ALU_MAP  = {
  :+ => :getpid,
  :& => :getgid,
  :>> => :getuid,
  :<< => :getppid,
  :^ => :geteuid,
  :- => :getegid,
  :* => :getpgrp,
  :| => :gettid,
  :/ => :fork,
}

def install_seccomp
  add = SYS[:getpid]
  bytes = SeccompTools::Asm.asm(<<-EOS)
    A = sys_number
    A >= 0x40000000 ? dead : next
    A == write ? check_arg0 : next
    A == #{SYS[ALU_MAP[:&]]} ? and : next
    A == #{SYS[ALU_MAP[:>>]]} ? shr : next
    A == #{SYS[ALU_MAP[:|]]} ? or : next
    A == #{SYS[ALU_MAP[:+]]} ? add : next
    A == #{SYS[ALU_MAP[:-]]} ? sub : next
    A == #{SYS[ALU_MAP[:*]]} ? mul : next
    A == #{SYS[ALU_MAP[:<<]]} ? shl : next
    A == #{SYS[ALU_MAP[:^]]} ? xor : next
    A == #{SYS[ALU_MAP[:/]]} ? div : next
    return ALLOW
  check_arg0:
    A = args[0]
    A == 0 ? dead : ok
  dead:
    return KILL
  mul:
    A = args[1]
    X = A
    A = args[0]
    A *= X
    A == 0 ? alu_return : alu_return
  add:
    A = args[1]
    X = A
    A = args[0]
    A += X
    A == 0 ? alu_return : alu_return
  shr:
    A = args[1]
    X = A
    A = args[0]
    A >>= X
    A == 0 ? alu_return : alu_return
  sub:
    A = args[1]
    X = A
    A = args[0]
    A -= X
    A == 0 ? alu_return : alu_return
  and:
    A = args[1]
    X = A
    A = args[0]
    A &= X
    A == 0 ? alu_return : alu_return
  xor:
    A = args[1]
    X = A
    A = args[0]
    A ^= X
    A == 0 ? alu_return : alu_return
  or:
    A = args[1]
    X = A
    A = args[0]
    A |= X
    A == 0 ? alu_return : alu_return
  shl:
    A = args[1]
    X = A
    A = args[0]
    A <<= X
    A == 0 ? alu_return : alu_return
  div:
    A = args[1]
    X = A
    A = args[0]
    A /= X
    A == 0 ? alu_return : alu_return
  alu_return:
    mem[0] = A
    A = args[2]
    X = A
    A = mem[0]
    A >>= X
    X = 0x30000
    A &= 0xffff
    A |= X
    return A
    ok:
    return ALLOW
  EOS
  scall(:prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0)
  # struct prog {
  #   unsigned short len;
  #   unsigned char *filter;
  # } rule = {
  #   .len = sizeof(filter) >> 3,
  #   .filter = filter
  # };
  put_val(bytes.size / 8, BUFFER_AT)
  put_val(BUFFER_AT + 16, BUFFER_AT + 8)
  bytes.unpack("L*").each_with_index do |v, i|
    put_val(v, BUFFER_AT + 16 + i * 4)
  end
  scall(:prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, BUFFER_AT)
end

# rip -= v
# this must be done in a faster way so we don't use alu32to
# XXX: this impl. will be wrong if (rip - v) >> 16 != rip >> 16
def dec_rip(v)
  scall(:set_tid_address, RegRef.new(15))
  scall(:prctl, PR_GET_TID_ADDRESS, SIGACTION_AT + 2)
  scall(ALU_MAP[:-], Reg.new(15), v, 0)
end

def alu32to(sym, a, b, regidx, clr_high: false)
  regidx = regidx.val if regidx.is_a?(Reg)
  scall(:set_tid_address, RegRef.new(regidx))
  scall(:prctl, PR_GET_TID_ADDRESS, SIGACTION_AT + 2)
  set_reg(0, a)
  set_reg(1, b)
  scall(ALU_MAP[sym], Reg.new(0), Reg.new(1), 0)
  scall(ALU_MAP[sym], Reg.new(0), Reg.new(1), 16)
  return unless clr_high
  scall(ALU_MAP[sym], 0, 0, 0)
  scall(ALU_MAP[sym], 0, 0, 0)
end

def random32
  @ary ||= [0x8d4f04b2, 0xe9ab109d, 0xf9de7e36, 0x33f33fe0, 0xd3c45f8c, 0x14220605, 0x1bd1fc38, 0x2c19574f, 0xaca81571, 0xb4f0b4fb, 0x8df954f3, 0x688620f9, 0x7785df55, 0x32e57ab6, 0x5c37a6db, 0x1e8b51cc, 0x2b0b575b, 0x468932dc, 0x69a33fff, 0x51fdd41a]
  @ary.pop
end

def xtea(v, output_addr)
  delta_immi = random32
  # void encrypt (uint32_t* v, uint32_t* k) {
  #   uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
  #   uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
  #   uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
  #   for (i=0; i < 32; i++) {                       /* basic cycle start */
  #       sum += delta;
  #       v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
  #       v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
  #   }                                              /* end cycle */
  #   v[0]=v0; v[1]=v1;
  # }

  # load keys to regs[2, 3, 4, 5]
  # load v to regs[6, 7]
  # sum is regs[8]
  # delta is regs[9]
  # i is regs[10]
  # tmp is regs[11, 12, 13, 14]
  keys = Array.new(4) { random32 }
  puts ".delta = #{delta_immi.hex}, .k = {#{keys.map(&:hex).join(', ')}},"
  k = []
  keys.each_with_index do |v, i|
    set_reg(i + 2, v)
    k[i] = Reg.new(i + 2)
  end
  load_reg32(6, v); v0 = Reg.new(6)
  load_reg32(7, v + 4); v1 = Reg.new(7)
  set_reg(8, 0); sum = Reg.new(8)
  set_reg(9, delta_immi); delta = Reg.new(9)
  set_reg(10, 0); i = Reg.new(10)
  tmp1 = Reg.new(11); tmp2 = Reg.new(12)
  for_loop = @rip
  # sum += delta;
  alu32to(:+, sum, delta, sum)
  # v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
  alu32to(:<<, v1, 4, tmp1); alu32to(:+, tmp1, k[0], tmp1)
  alu32to(:>>, v1, 5, tmp2); alu32to(:+, tmp2, k[1], tmp2)
  alu32to(:^, tmp1, tmp2, tmp1)
  alu32to(:+, v1, sum, tmp2)
  alu32to(:^, tmp1, tmp2, tmp1)
  alu32to(:+, v0, tmp1, v0)
  # v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
  alu32to(:<<, v0, 4, tmp1); alu32to(:+, tmp1, k[2], tmp1)
  alu32to(:>>, v0, 5, tmp2); alu32to(:+, tmp2, k[3], tmp2)
  alu32to(:^, tmp1, tmp2, tmp1)
  alu32to(:+, v0, sum, tmp2)
  alu32to(:^, tmp1, tmp2, tmp1)
  alu32to(:+, v1, tmp1, v1)
  alu32to(:+, i, 1, i)
  predict_end_rip = for_loop + 171
  alu32to(:>>, i, 5, tmp1); alu32to(:-, 1, tmp1, tmp1); alu32to(:*, tmp1, predict_end_rip - for_loop, tmp1)
  dec_rip(tmp1)
  if predict_end_rip != @rip
    log.dump(@rip)
    log.dump(predict_end_rip)
    fail
  end
  put_val(v0, output_addr)
  put_val(v1, output_addr + 4)
end

# Fancy not
# XXX: regs[idx + 1] will be used as a tmp
def not_r(idx)
  fail unless 2 <= idx and idx <= 13
  r = Reg.new(idx)
  tmp = Reg.new(idx + 1)
  # r = r & -r
  alu32to(:-, 0, r, tmp)
  alu32to(:&, r, tmp, r)
  # r %= 3
  alu32to(:/, r, 3, tmp)
  alu32to(:*, tmp, 3, tmp)
  alu32to(:-, r, tmp, r)
  # r = (2 ^ r) / 2
  alu32to(:^, 2, r, r)
  alu32to(:>>, r, 1, r)
end

def check
  expect = [
    0x152ceed2, 0xd6046dc3,
    0x4a9d3ffd, 0xbb541082,
    0x632a4f78, 0x0a9cb93d,
    0x58aae351, 0x92012a14,
  ]
  # given the ciphertext doesn't contain null bytes, we can load them through load_reg
  # always use regs[9] to load output, and assume regs[10] screwed
  # FOR(i, 8) regs[2] |= output[i] ^ expect[i]
  8.times do |i|
    load_reg(9, BUFFER_AT + i * 4)
    set_reg(2, 0)
    alu32to(:^, Reg.new(9), expect[i], 3)
    alu32to(:|, Reg.new(2), Reg.new(3), 2)
  end
  not_r(2)
  msg = "Congratulations! Here is your flag: "
  fail if msg.size % 4 != 0
  msg.unpack("L*").each_with_index do |v, i|
    put_val(v, BUFFER_AT + i * 4)
  end
  # ruin whatever after INPUT, we don't care anymore
  put_val("\n".ord, INPUT_AT + INPUT_SIZE)
  # will be killed by seccomp if regs[2] == 0
  scall(:write, Reg.new(2), BUFFER_AT, msg.size)
  scall(:write, Reg.new(2), INPUT_AT, INPUT_SIZE + 1)
end

set_reg(0, MEM)
scall(:mmap, Reg.new(0), 0x1, 7, 0x22, 0, 0)
scall(:read, 0, INPUT_AT, INPUT_SIZE)
install_sigaction
install_seccomp
xtea(INPUT_AT, BUFFER_AT)
xtea(INPUT_AT + 8, BUFFER_AT + 8)
xtea(INPUT_AT + 16, BUFFER_AT + 16)
xtea(INPUT_AT + 24, BUFFER_AT + 24)
check
