require 'securerandom'
require 'pwn'

ROUNDS = 765
BITS = 128
PAIRS = 6

def encrypt(msg, key)
  enc = msg
  mask = (1 << BITS) - 1
  ROUNDS.times do
    enc = (enc + key) & mask
    enc = enc ^ key
  end
  enc
end

def decrypt(msg, key)
  enc = msg
  mask = (1 << BITS) - 1
  ROUNDS.times do
    enc = enc ^ key
    enc = (enc - key) & mask
  end
  enc
end

fail unless BITS % 8 == 0

pairs = [
  [0x29abc13947b5373b86a1dc1d423807a, 0xb36b6b62a7e685bd1158744662c5d04a],
  [0xeeb83b72d3336a80a853bf9c61d6f254, 0x614d86b5b6653cdc8f33368c41e99254],
  [0x7a0e5ffc7208f978b81475201fbeb3a0, 0x292a7ff7f12b4e21db00e593246be5a0],
  [0xc464714f5cdce458f32608f8b5e2002e, 0x64f930da37d494c634fa22a609342ffe],
  [0xf944aaccf6779a65e8ba74795da3c41d, 0xaa3825e62d053fb0eb8e7e2621dabfe7],
  [0x552682756304d662fa18e624b09b2ac5, 0xf2ffdf4beb933681844c70190ecf60bf]
]

kk = []
16.times do |t|
  ret = 256.times.find_all do |c|
    now = [*kk, c].reverse.reduce(0) { |d, v| d * 256 + v }
    msk = (1 << ((kk.size + 1) * 8 + 1)) - 1
    pairs.all? do |pl, e|
      encrypt(pl, now) & msk == e & msk
    end
  end
  p ret if ret.size != 1
  # fail if ret.size > 1
  kk << ret[0]
  p kk
end

key = kk.reverse.reduce(0) { |d, v| d * 256 + v }
p 'TWCTF{%x}' % decrypt(0x43713622de24d04b9c05395bb753d437, key)
