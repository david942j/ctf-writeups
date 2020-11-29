#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'digest'
require 'elftools' # gem install elftools
require 'fileutils'

PG_SZ = 0x1000
RX = 0xdead0000
RW = 0x02170000

def gen_path(data)
  filename = Digest::SHA1.hexdigest(data)
  dir = ENV['TENET_TMP_DIR'] || '/tmp/tenet'
  FileUtils.mkdir_p(dir, mode: 0o700)
  File.join(dir, filename)
end

def create_ehdr
  ::ELFTools::Structs::ELF_Ehdr.new(endian: :little).tap do |h|
    h.elf_class = 64
    h.e_ident.magic = ::ELFTools::Constants::ELFMAG
    h.e_ident.ei_class = 2 # 64-bit
    h.e_ident.ei_data = 1 # little endian
    h.e_ident.ei_version = 1
    h.e_ident.ei_padding = "\x00" * 7
    h.e_type = ::ELFTools::Constants::ET::ET_EXEC
    h.e_machine = ::ELFTools::Constants::EM::EM_X86_64
    h.e_ehsize = h.num_bytes
  end
end

def create_phdr(vma, perm)
  ::ELFTools::Structs::ELF_Phdr[64].new(endian: :little).tap do |h|
    h.p_type = ::ELFTools::Constants::PT::PT_LOAD
    h.p_offset = 0
    h.p_vaddr = vma
    h.p_paddr = vma
    h.p_flags = perm
    h.p_align = PG_SZ
  end
end

def make_elf(sc)
  # ELF header
  # three program headers
  # <padding to 4096>
  # shellcode
  ehdr = create_ehdr
  load1 = create_phdr(RX, 5)
  load2 = create_phdr(RW, 6)
  gnu_stk = ::ELFTools::Structs::ELF_Phdr[64].new(endian: :little).tap do |h|
    h.p_type = ::ELFTools::Constants::PT::PT_GNU_STACK
    h.p_flags = 6
    h.p_align = 0x10
  end

  ehdr.e_phentsize = load1.num_bytes
  ehdr.e_phnum = 3
  ehdr.e_entry = RX
  ehdr.e_phoff = ehdr.num_bytes
  load1.p_offset = PG_SZ
  load1.p_filesz = load1.p_memsz = sc.size
  load2.p_filesz = 1
  load2.p_memsz = PG_SZ
  elf = ([ehdr, load1, load2, gnu_stk].map(&:to_binary_s).join).ljust(PG_SZ, "\x00") + sc
  gen_path(sc).tap do |path|
    File.open(path, 'wb', 0o750) { |f| f.write(elf) }
  end
end

def prepare_sc
  "\xEBZj&_j\x01^1\xC0\xB0\x9D\x0F\x05j\x16_H\x8D\x15\x14\x00\x00\x00Rj\x06H\x89\xE2j\x02^1\xC0\xB0\x9D\x0F\x05H\x83\xC4\x10\xC3 \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x02>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x00\x15\x00\x01\x00\v\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\xE8\xA1\xFF\xFF\xFFH\x89\xE7H\x81\xE7\x00\xF0\xFF\xFFH\x81\xEF\x00\x10\x02\x00H\xC7\xC6\x00@\x02\x00H1\xC0\xB0\v\x0F\x05"
end

def main
  puts "Size of shellcode? (MAX: 2000)"
  len = gets.to_i
  return puts "ಠ_ಠ" if len <= 0 || len > 2000
  puts "Reading #{len} bytes.."
  sc = STDIN.read(len)
  return puts "EOF" if sc.size != len
  path = make_elf(prepare_sc + sc)
  puts "Shellcode receieved. Launching Time Machine.."
  sleep(1)
  Process.exec(File.join(__dir__, "time_machine"), path)
end 

STDIN.sync = 0
STDOUT.sync = 0
main
