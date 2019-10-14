if ARGV.size != 2
  STDERR.puts "Usage: ./suicune <flag> <key>"
  exit 1
end

flag = ARGV[0].bytes
key = ARGV[1].to_i & 65535
class Array(T)
  def next_perm : Bool
    (self.size - 2).downto(0) do |i|
      if self[i] < self[i + 1]
        (self.size - 1).downto(i + 1) do |j|
          if self[j] > self[i]
            self[i], self[j] = self[j], self[i]
            self[i+1 .. -1] = self[i+1 .. -1].reverse
            return true
          end
        end
      end
    end

    false
  end

  def nth_perm(n) : Array(T)
    return self if n <= 0

    while n > 0
      n -= 1
      break if !next_perm
    end
    self
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
