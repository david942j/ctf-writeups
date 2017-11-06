#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'elftools'   # https://github.com/david942j/rbelftools

context.arch = 'amd64'
file = ARGV[0] # 'source_27c87e03d4cf77d4acb6a34524a1ee71'
@whole = IO.binread(file)
context.log_level = 10
@elf = ELF.new(file, checksec: false)
def elf_file; @elf.instance_variable_get(:@elf_file); end

def patch(offset, to)
  @whole[offset, to.size] = to
end

def gnu_note
  elf_file.sections_by_type(:note).last
end

def eh_frame
  elf_file.section_by_name('.eh_frame')
end

def patch_fini_array
  fini_array = elf_file.section_by_name('.fini_array')
  # patch fini_array's t
  pos = fini_array.header.sh_offset + 8
  rel = elf_file.section_by_name('.rela.dyn').each_relocations.find { |rel| rel.header.r_offset == pos + 0x200000 }
  rel.header.r_addend = do_mprotect - 5

  # patch section fini_array's size, this can cheat IDA
  fini_array.header.sh_size = 8
end

def offset_of(section_name)
  elf_file.section_by_name(section_name).header.sh_addr
end

def do_mprotect
  eh_frame.header.sh_addr + 217 + 5 + 20
end

def concat_offset
  do_mprotect + 0x15
end

def input_offset
  @elf.symbols.s
end

def write_buildid
  # check input[15] == '!'
  slot, as = 15, '!'
  rdi = do_mprotect
  sc = asm(<<-EOS)
  pop rdi
  mov al, BYTE PTR [rdi + #{input_offset - rdi + slot}]
  cmp al, #{as.ord}
  jne ret
  call rdi
  add rdi, #{concat_offset - do_mprotect}
  jmp rdi
ret:
  ret
  EOS
  puts disasm(sc)
  patch(gnu_note.header.sh_addr + 0x10, sc)
end

def dump_roundkeys(addr)
  p "{" + @whole[addr, 16 * 11].bytes.join(', ') + "}"
end

def write_ehframe
  # rbx: unsigned char* plain
  # rsi: unsigned char* round_keys
  aes_sc_offset = offset_of('.eh_frame') + 16 + 7 # skip enc result
  dump_roundkeys(offset_of('.eh_frame') - 176)
  aes = asm(<<-EOS)
  mov rsi, rbx
  sub si, #{aes_sc_offset - offset_of('.eh_frame') + 176} # use whatever garbage as round_keys
  add rbx, #{input_offset - aes_sc_offset}
  movdqu xmm1, XMMWORD PTR [rbx]
  movdqu xmm0, XMMWORD PTR [rsi]
  pxor xmm1, xmm0
  push 10
  pop rdi
loop:
  add rsi, 0x10
  movdqu xmm0, XMMWORD PTR [rsi]
  dec edi
  test edi, edi
  jz last
  js out
  aesenc xmm1, xmm0
  jmp loop
last:
  aesenclast xmm1, xmm0
  jmp loop
out:
  EOS
  sc = aes + asm(<<-EOS)
  ucomisd xmm0, xmm1 # wrong..
  je ok
  ret
ok:
  EOS
  here = aes_sc_offset + sc.size
  sc += asm(<<-EOS)
  neg edi # edi = 1
  push rdi
  pop rax
  add rsi, 0x10 # skip enc result
  call #{do_mprotect + 0xe - here} # so hard.. jump to push 7; pop rdx;
  EOS
  puts disasm sc
  enc_res = ['e7470412496dcf47b0e91b1767fb4628'].pack("H*")
  sc = enc_res + "Good!\n\x00" + sc
  puts 'long sc size = ' + sc.size.to_s
  now = offset_of('.eh_frame')
  loop do
    next now += 1 if @whole[now] == "\x00"
    len = @whole.index("\x00", now) - now
    # next now += len if len <= 1
    sc_len = len - 1
    sc_len = [sc.size, sc_len].min
    @whole[now] = sc_len.chr
    @whole[now + 1, sc_len] = sc[0, sc_len]
    sc = sc[sc_len..-1]
    now += sc_len + 1
    break @whole[now] = "\xff" if sc.empty?
  end
  puts "Gap remained: #{do_mprotect - 5 - now - 1}"

  sc = asm(<<-EOS)
  call #{gnu_note.header.sh_addr + 0x10 - do_mprotect + 5}
  EOS
  patch(do_mprotect - 5, sc)

  # mprotect here as rwx
  rdi = do_mprotect
  sc = asm(<<-EOS)
  push 10
  pop rax
  push rdi
  sub di, #{rdi}
  mov esi, 0x1000
  push 7
  pop rdx
  syscall
  pop rdi
  ret
# concat shellcodes
# now rdi = rip
  xor ecx, ecx
  add di, #{offset_of('.eh_frame') - concat_offset}
  push rdi
  push rdi
  pop rsi
  pop rbx
loop:
  mov cl, BYTE PTR [rsi]
  test cl, cl
  js go
  inc rsi
  rep movsb
  jmp loop
go:
  add bx, #{aes_sc_offset - offset_of('.eh_frame')}
  jmp rbx
  EOS
  puts disasm(sc)
  space = eh_frame.header.sh_size + eh_frame.header.sh_addr - do_mprotect
  puts "eh_frame remained: #{space - sc.size}"
  raise StandardError, sc.size.to_s if sc.size > space
  patch(do_mprotect, sc)
end

patch_fini_array
write_buildid
write_ehframe
elf_file.patches.each { |key, val| patch(key, val) }

IO.binwrite(file + '.patch', @whole)
`strip #{file + '.patch'}`
