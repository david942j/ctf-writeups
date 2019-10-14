exit 1 if ARGV.size != 2

flag = ARGV[0].bytes
key = ARGV[1].to_i & 65535

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

  def enhex
    self.reduce("") { |s, c| s + "%02x" % c }
  end
end

r = Random.new(key)
16.times do
  x = 256.times.map(&.to_u8).to_a.shuffle(random: r)[0, flag.size]
  z = r.rand(UInt64)
  flag = flag.zip(x.nth_perm(z)).map { |a, b| a ^ b }.reverse
end
puts flag.enhex
