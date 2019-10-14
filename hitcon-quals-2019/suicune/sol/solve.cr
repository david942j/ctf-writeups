s = STDIN.gets
exit 2 if s.nil?

enc = s.chars.each_slice(2).map { |(a, b)| (a.to_s+b.to_s).to_u8(16) }.to_a
SIZE = 49
raise ArgumentError.new("size should be %d but got %d" % [SIZE, enc.size]) if enc.size != SIZE

class Array(T)
  def nth_perm(n) : Array(T)
    raise OverflowError.new if n == UInt64::MAX
    return self.dup if n <= 0

    ret = self.dup
    fact = 1_u64
    f = 2_u64
    (self.size - 2).downto(0) do |i|
      if ret[i] < ret[i + 1]
        (self.size - 1).downto(i + 1) do |j|
          if ret[j] > ret[i]
            ret[i], ret[j] = ret[j], ret[i]
            if n >= fact
              return ret.nth_perm(n - fact)
            else
              ret[i+1 .. -1] = ret[i+1 .. -1].reverse
              return ret.nth_perm(n - 1)
            end
          end
        end
      end
      if fact > UInt64::MAX / f
        fact = UInt64::MAX
      else
        fact = fact * f
      end
      f += 1
    end
    ret
  end
end

def gen_key(seed)
  r = Random.new(seed)
  key = [0.to_u8] * SIZE
  16.times do
    x = 256.times.map(&.to_u8).to_a.shuffle(random: r)[0, SIZE]
    z = r.rand(UInt64)
    key = key.zip(x.nth_perm(z)).map { |a, b| a ^ b }.reverse
  end
  key
end

def dec(enc, seed)
  enc.zip(gen_key(seed)).map { |a, b| a ^ b }
end

65536.times do |s|
  print "." if s % 1000 == 0
  r = dec(enc, s).map(&.chr).join
  if r.starts_with?("hitcon")
    puts "Key = %d" % s
    puts r
    break
  end
end
