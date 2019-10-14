#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

if ARGV.size != 4
  puts "Usage: ./upload.rb <IP> <PORT> <PASSWORD> <BIN_PATH>"
  exit(2)
end

host = ARGV[0]
port = ARGV[1].to_i
password = ARGV[2].strip
bin = IO.binread(ARGV[3])
$z = Sock.new(host, port)
def z; $z; end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!
z.gets 'Password'
z.puts password
z.gets "M)\n"
z.puts bin.size
z.write bin

z.interact
