# twofish.rb
#
# Author:: Martin Carpenter
# Email:: martin.carpenter@gmail.com
# Copyright:: Copyright (c) Martin Carpenter 2009
#
# Implements a class for symmetric encryption using the Twofish
# encryption algorithm based on original work by Guido Flohr.
require 'securerandom'
class Twofish

  attr_reader :iv

  BLOCK_SIZE = 16

  def initialize(opts={})
    @iv = opts[:iv]

    key = IO.binread('key').lines

    @k = key[0].split(', ').map { |v| v.to_i(16) }
    @xS0 = key[1].split(', ').map { |v| v.to_i(16) }
    @xS1 = key[2].split(', ').map { |v| v.to_i(16) }
    @xS2 = key[3].split(', ').map { |v| v.to_i(16) }
    @xS3 = key[4].split(', ').map { |v| v.to_i(16) }
    # IO.binwrite('key',[@k.map{|v|'0x%x' % v}.join(', '),
          # @xS0.map{|v|'0x%x' % v}.join(', '),
          # @xS1.map{|v|'0x%x' % v}.join(', '),
          # @xS2.map{|v|'0x%x' % v}.join(', '),
          # @xS3.map{|v|'0x%x' % v}.join(', '),
    # ].join("\n"))
  end

  def decrypt(ciphertext)
    ciphertext = to_binary(ciphertext.dup)
    fail unless (ciphertext.length % BLOCK_SIZE).zero?
    result = to_binary('')
    @to_xor ||= @iv
    (0...ciphertext.length).step(BLOCK_SIZE) do |block_ptr|
      ciphertext_block = ciphertext[block_ptr, BLOCK_SIZE]
      plaintext_block = decrypt_block(ciphertext_block)
      xor_block!(plaintext_block, @to_xor)
      result << plaintext_block
      @to_xor = ciphertext_block
    end
    result
  end

  private

  def xor_block!(target, source)
    (0...BLOCK_SIZE).each { |i| target[i] = (target[i].ord ^ source[i].ord).chr }
  end

  def decrypt_block(plain)

    words = plain.unpack("V4")

    r0 = @k[4] ^ words[0]
    r1 = @k[5] ^ words[1]
    r2 = @k[6] ^ words[2]
    r3 = @k[7] ^ words[3]

    # i = 7
    t0 = @xS0[r0 & 0xff] ^
         @xS1[r0 >> 8 & 0xff] ^
         @xS2[r0 >> 16 & 0xff] ^
         @xS3[r0 >> 24 & 0xff]
    t1 = @xS0[r1 >> 24 & 0xff] ^
         @xS1[r1 & 0xff] ^
         @xS2[r1 >> 8 & 0xff] ^
         @xS3[r1 >> 16 & 0xff]

    r2 = r2 >> 31 & 0x1 | (r2 & 0x7fffffff) << 1
    r2 ^= 0xffffffff & (t0 + t1 + @k[38])

    r3 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[39])
    r3 = r3 >> 1 & 0x7fffffff | (r3 & 0x1) << 31

    t0 = @xS0[r2 & 0xff] ^
         @xS1[r2 >> 8 & 0xff] ^
         @xS2[r2 >> 16 & 0xff] ^
         @xS3[r2 >> 24 & 0xff]
    t1 = @xS0[r3 >> 24 & 0xff] ^
         @xS1[r3 & 0xff] ^
         @xS2[r3 >> 8 & 0xff] ^
         @xS3[r3 >> 16 & 0xff]

    r0 = r0 >> 31 & 0x1 | (r0 & 0x7fffffff) << 1
    r0 ^= 0xffffffff & (t0 + t1 + @k[36])

    r1 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[37])
    r1 = r1 >> 1 & 0x7fffffff | (r1 & 0x1) << 31

    # i = 6
    t0 = @xS0[r0 & 0xff] ^
         @xS1[r0 >> 8 & 0xff] ^
         @xS2[r0 >> 16 & 0xff] ^
         @xS3[r0 >> 24 & 0xff]
    t1 = @xS0[r1 >> 24 & 0xff] ^
         @xS1[r1 & 0xff] ^
         @xS2[r1 >> 8 & 0xff] ^
         @xS3[r1 >> 16 & 0xff]

    r2 = r2 >> 31 & 0x1 | (r2 & 0x7fffffff) << 1
    r2 ^= 0xffffffff & (t0 + t1 + @k[34])

    r3 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[35])
    r3 = r3 >> 1 & 0x7fffffff | (r3 & 0x1) << 31

    t0 = @xS0[r2 & 0xff] ^
         @xS1[r2 >> 8 & 0xff] ^
         @xS2[r2 >> 16 & 0xff] ^
         @xS3[r2 >> 24 & 0xff]
    t1 = @xS0[r3 >> 24 & 0xff] ^
         @xS1[r3 & 0xff] ^
         @xS2[r3 >> 8 & 0xff] ^
         @xS3[r3 >> 16 & 0xff]

    r0 = r0 >> 31 & 0x1 | (r0 & 0x7fffffff) << 1
    r0 ^= 0xffffffff & (t0 + t1 + @k[32])

    r1 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[33])
    r1 = r1 >> 1 & 0x7fffffff | (r1 & 0x1) << 31

    # i = 5
    t0 = @xS0[r0 & 0xff] ^
         @xS1[r0 >> 8 & 0xff] ^
         @xS2[r0 >> 16 & 0xff] ^
         @xS3[r0 >> 24 & 0xff]
    t1 = @xS0[r1 >> 24 & 0xff] ^
         @xS1[r1 & 0xff] ^
         @xS2[r1 >> 8 & 0xff] ^
         @xS3[r1 >> 16 & 0xff]

    r2 = r2 >> 31 & 0x1 | (r2 & 0x7fffffff) << 1
    r2 ^= 0xffffffff & (t0 + t1 + @k[30])

    r3 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[31])
    r3 = r3 >> 1 & 0x7fffffff | (r3 & 0x1) << 31

    t0 = @xS0[r2 & 0xff] ^
         @xS1[r2 >> 8 & 0xff] ^
         @xS2[r2 >> 16 & 0xff] ^
         @xS3[r2 >> 24 & 0xff]
    t1 = @xS0[r3 >> 24 & 0xff] ^
         @xS1[r3 & 0xff] ^
         @xS2[r3 >> 8 & 0xff] ^
         @xS3[r3 >> 16 & 0xff]

    r0 = r0 >> 31 & 0x1 | (r0 & 0x7fffffff) << 1
    r0 ^= 0xffffffff & (t0 + t1 + @k[28])

    r1 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[29])
    r1 = r1 >> 1 & 0x7fffffff | (r1 & 0x1) << 31

    # i = 4
    t0 = @xS0[r0 & 0xff] ^
         @xS1[r0 >> 8 & 0xff] ^
         @xS2[r0 >> 16 & 0xff] ^
         @xS3[r0 >> 24 & 0xff]
    t1 = @xS0[r1 >> 24 & 0xff] ^
         @xS1[r1 & 0xff] ^
         @xS2[r1 >> 8 & 0xff] ^
         @xS3[r1 >> 16 & 0xff]

    r2 = r2 >> 31 & 0x1 | (r2 & 0x7fffffff) << 1
    r2 ^= 0xffffffff & (t0 + t1 + @k[26])

    r3 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[27])
    r3 = r3 >> 1 & 0x7fffffff | (r3 & 0x1) << 31

    t0 = @xS0[r2 & 0xff] ^
         @xS1[r2 >> 8 & 0xff] ^
         @xS2[r2 >> 16 & 0xff] ^
         @xS3[r2 >> 24 & 0xff]
    t1 = @xS0[r3 >> 24 & 0xff] ^
         @xS1[r3 & 0xff] ^
         @xS2[r3 >> 8 & 0xff] ^
         @xS3[r3 >> 16 & 0xff]

    r0 = r0 >> 31 & 0x1 | (r0 & 0x7fffffff) << 1
    r0 ^= 0xffffffff & (t0 + t1 + @k[24])

    r1 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[25])
    r1 = r1 >> 1 & 0x7fffffff | (r1 & 0x1) << 31

    # i = 3
    t0 = @xS0[r0 & 0xff] ^
         @xS1[r0 >> 8 & 0xff] ^
         @xS2[r0 >> 16 & 0xff] ^
         @xS3[r0 >> 24 & 0xff]
    t1 = @xS0[r1 >> 24 & 0xff] ^
         @xS1[r1 & 0xff] ^
         @xS2[r1 >> 8 & 0xff] ^
         @xS3[r1 >> 16 & 0xff]

    r2 = r2 >> 31 & 0x1 | (r2 & 0x7fffffff) << 1
    r2 ^= 0xffffffff & (t0 + t1 + @k[22])

    r3 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[23])
    r3 = r3 >> 1 & 0x7fffffff | (r3 & 0x1) << 31

    t0 = @xS0[r2 & 0xff] ^
         @xS1[r2 >> 8 & 0xff] ^
         @xS2[r2 >> 16 & 0xff] ^
         @xS3[r2 >> 24 & 0xff]
    t1 = @xS0[r3 >> 24 & 0xff] ^
         @xS1[r3 & 0xff] ^
         @xS2[r3 >> 8 & 0xff] ^
         @xS3[r3 >> 16 & 0xff]

    r0 = r0 >> 31 & 0x1 | (r0 & 0x7fffffff) << 1
    r0 ^= 0xffffffff & (t0 + t1 + @k[20])

    r1 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[21])
    r1 = r1 >> 1 & 0x7fffffff | (r1 & 0x1) << 31

    # i = 2
    t0 = @xS0[r0 & 0xff] ^
         @xS1[r0 >> 8 & 0xff] ^
         @xS2[r0 >> 16 & 0xff] ^
         @xS3[r0 >> 24 & 0xff]
    t1 = @xS0[r1 >> 24 & 0xff] ^
         @xS1[r1 & 0xff] ^
         @xS2[r1 >> 8 & 0xff] ^
         @xS3[r1 >> 16 & 0xff]

    r2 = r2 >> 31 & 0x1 | (r2 & 0x7fffffff) << 1
    r2 ^= 0xffffffff & (t0 + t1 + @k[18])

    r3 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[19])
    r3 = r3 >> 1 & 0x7fffffff | (r3 & 0x1) << 31

    t0 = @xS0[r2 & 0xff] ^
         @xS1[r2 >> 8 & 0xff] ^
         @xS2[r2 >> 16 & 0xff] ^
         @xS3[r2 >> 24 & 0xff]
    t1 = @xS0[r3 >> 24 & 0xff] ^
         @xS1[r3 & 0xff] ^
         @xS2[r3 >> 8 & 0xff] ^
         @xS3[r3 >> 16 & 0xff]

    r0 = r0 >> 31 & 0x1 | (r0 & 0x7fffffff) << 1
    r0 ^= 0xffffffff & (t0 + t1 + @k[16])

    r1 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[17])
    r1 = r1 >> 1 & 0x7fffffff | (r1 & 0x1) << 31

    # i = 1
    t0 = @xS0[r0 & 0xff] ^
         @xS1[r0 >> 8 & 0xff] ^
         @xS2[r0 >> 16 & 0xff] ^
         @xS3[r0 >> 24 & 0xff]
    t1 = @xS0[r1 >> 24 & 0xff] ^
         @xS1[r1 & 0xff] ^
         @xS2[r1 >> 8 & 0xff] ^
         @xS3[r1 >> 16 & 0xff]

    r2 = r2 >> 31 & 0x1 | (r2 & 0x7fffffff) << 1
    r2 ^= 0xffffffff & (t0 + t1 + @k[14])

    r3 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[15])
    r3 = r3 >> 1 & 0x7fffffff | (r3 & 0x1) << 31

    t0 = @xS0[r2 & 0xff] ^
         @xS1[r2 >> 8 & 0xff] ^
         @xS2[r2 >> 16 & 0xff] ^
         @xS3[r2 >> 24 & 0xff]
    t1 = @xS0[r3 >> 24 & 0xff] ^
         @xS1[r3 & 0xff] ^
         @xS2[r3 >> 8 & 0xff] ^
         @xS3[r3 >> 16 & 0xff]

    r0 = r0 >> 31 & 0x1 | (r0 & 0x7fffffff) << 1
    r0 ^= 0xffffffff & (t0 + t1 + @k[12])

    r1 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[13])
    r1 = r1 >> 1 & 0x7fffffff | (r1 & 0x1) << 31

    # i = 0
    t0 = @xS0[r0 & 0xff] ^
         @xS1[r0 >> 8 & 0xff] ^
         @xS2[r0 >> 16 & 0xff] ^
         @xS3[r0 >> 24 & 0xff]
    t1 = @xS0[r1 >> 24 & 0xff] ^
         @xS1[r1 & 0xff] ^
         @xS2[r1 >> 8 & 0xff] ^
         @xS3[r1 >> 16 & 0xff]

    r2 = r2 >> 31 & 0x1 | (r2 & 0x7fffffff) << 1
    r2 ^= 0xffffffff & (t0 + t1 + @k[10])

    r3 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[11])
    r3 = r3 >> 1 & 0x7fffffff | (r3 & 0x1) << 31

    t0 = @xS0[r2 & 0xff] ^
         @xS1[r2 >> 8 & 0xff] ^
         @xS2[r2 >> 16 & 0xff] ^
         @xS3[r2 >> 24 & 0xff]
    t1 = @xS0[r3 >> 24 & 0xff] ^
         @xS1[r3 & 0xff] ^
         @xS2[r3 >> 8 & 0xff] ^
         @xS3[r3 >> 16 & 0xff]

    r0 = r0 >> 31 & 0x1 | (r0 & 0x7fffffff) << 1
    r0 ^= 0xffffffff & (t0 + t1 + @k[8])

    r1 ^= 0xffffffff & (t0 + ((t1 & 0x7fffffff) << 1) + @k[9])
    r1 = r1 >> 1 & 0x7fffffff | (r1 & 0x1) << 31

    [@k[0] ^ r2, @k[1] ^ r3, @k[2] ^ r0, @k[3] ^ r1].pack("V4")
  end

  private

  def to_binary(s)
    s.respond_to?(:force_encoding) ? s.force_encoding('BINARY') : s
  end
end
