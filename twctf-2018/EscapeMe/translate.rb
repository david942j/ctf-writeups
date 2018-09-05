require 'pwn'

class << self
  extend Pwn
  include Pwnlib

  def translate(base, addr, bit2 = 0, bit4 = 1)
    ret = -1
    cr3 = 0xa000
    mem_map = base + cr3
    msk = 1 | (bit2 << 1) | (bit4 << 2)
    c39 = (addr >> 39) & 0x1ff
    v39 = rr(mem_map + c39 * 8)
    log.info "v39 = #{v39.hex}"
    return log.error('msk fail') unless (v39 & msk) == msk
    c30 = (addr >> 30) & 0x1ff
    v30 = rr(base + (v39 & -4096) + c30 * 8)
    log.info "v30 = #{v30.hex}"
    return log.error('msk fail') unless (v30 & msk) == msk
    c21 = (addr >> 21) & 0x1ff
    v21 = rr(base + (v30 & -4096) + c21 * 8)
    log.info "v21 = #{v21.hex}"
    return log.error('msk fail') unless (v21 & msk) == msk
    if (v21 & 0x80) == 0x80
      log.info('0x80 phase')
      if (v21 & 4) == 0
        ret = (v21 & -4096) | (addr & 0x1FFFFF)
      end
    else
      c12 = (addr >> 12) & 0x1ff
      v12 = rr(base + (v21 & -4096) + c12 * 8)
      log.info "v12 = #{v12.hex}"
      return log.error('msk fail') unless (v12 & msk) == msk
      ret = (v12 & -4096) | (addr & 0xfff)
    end
    log.info "ret = #{ret.hex}"
  end

  def rr(mem)
    gdb.readm(mem, 1, as: :u64)
  end
end
