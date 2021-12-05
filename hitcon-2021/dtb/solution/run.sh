#!/bin/bash

qemu-system-aarch64 -M virt,dtb=hack.dtb \
  -nographic -monitor none \
  -smp 1 -m 2048 \
  -kernel ../release/Image.gz -append "console=ttyAMA0 panic=-1 oops=panic" \
  -initrd ../release/rootfs.cpio.gz \
  -no-reboot -cpu cortex-a72
