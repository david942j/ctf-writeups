FLAG1 ?= <FLAG1 WILL BE HERE>
FLAG2 ?= <FLAG2 WILL BE HERE>
DISK ?= disk
INIT ?= init

all: qemu kernel user test solution fs

release: qemu kernel user
	rm -fr release/disk_clean
	tar xf disk_clean.tar.gz -C release/
	# bios
	mkdir -p release/pc-bios
	cp qemu/build/pc-bios/bios-256k.bin release/pc-bios
	cp qemu/build/pc-bios/kvmvapic.bin release/pc-bios
	cp qemu/build/pc-bios/linuxboot_dma.bin release/pc-bios
	cp qemu/build/pc-bios/vgabios-stdvga.bin release/pc-bios
	cp qemu/build/pc-bios/efi-e1000.rom release/pc-bios
	# qemu
	mkdir -p release/x86_64-softmmu
	cp qemu/build/x86_64-softmmu/qemu-system-x86_64 release/x86_64-softmmu
	# kernel
	cp linux/arch/x86_64/boot/bzImage release/
	cp linux/drivers/misc/tpu/tpu.ko release/
	cp linux/drivers/misc/tpu/tpu.ko release/disk_clean
	# user
	cp src/luna release/luna
	cp src/luna release/disk_clean/home/poe/
	$(MAKE) DISK=release/disk_clean INIT=init_release fs
	rm -fr release/disk_clean
	cd release && tar cvfz ../poe.tar.gz *

deploy: .PHONY
	$(MAKE) 'FLAG1=<FLAG1 WILL BE HERE>' 'FLAG2=<FLAG2 WILL BE HERE>' release
	rm -fr deploy/disk deploy/x86_64-softmmu deploy/pc-bios
	tar xf disk_clean.tar.gz -C deploy/
	mv deploy/disk_clean deploy/disk
	cp -r release/pc-bios release/x86_64-softmmu release/bzImage deploy/
	cp release/tpu.ko deploy/disk/
	cp release/luna deploy/disk/home/poe
	$(MAKE) DISK=deploy/disk INIT=init_release fs
	mv deploy/initramfs.cpio.gz deploy/poe1.cpio.gz
	cd deploy && tar cvfz ../deploy.tar.gz *

fs:
	echo "$(FLAG1)" > $(DISK)/home/poe/flag1
	echo "$(FLAG2)" > $(DISK)/flag2
	cp src/disk/$(INIT) $(DISK)/init
	cd $(DISK) && find . | cpio -o -Hnewc | gzip -9 > ../initramfs.cpio.gz

test:
	$(MAKE) -C tests
	rm -fr disk/tests/
	cp -r tests/ disk/
	$(MAKE) fs

solution:
	$(MAKE) -C sol
	cp sol/cord_exp disk/
	cp sol/tpu_exp disk/
	$(MAKE) fs

user: src/luna.c
	$(CXX) src/luna.c -o src/luna -I./src/linux/include/uapi/ -static
	cp src/luna disk/home/poe/
	$(MAKE) fs

qemu: src/qemu/hw/misc/tpu.c src/qemu/hw/misc/tpu-ir.h
	cp src/qemu/hw/misc/tpu.c qemu/hw/misc/
	cp src/qemu/hw/misc/tpu-ir.h qemu/hw/misc/
	# mkdir -p qemu/build && cd /home/PoE/qemu/build && ../configure --target-list=x86_64-softmmu && make -j `nproc`
	cd /home/PoE/qemu/build && make -j `nproc`
	strip --strip-debug qemu/build/x86_64-softmmu/qemu-system-x86_64

kernel: src/linux/drivers/misc/tpu/tpu-*.c src/linux/drivers/misc/tpu/tpu-*.h src/linux/include/uapi/linux/cord.h
	rm -rf linux/drivers/misc/tpu
	cp -r src/linux/drivers/misc/tpu linux/drivers/misc/
	cp src/qemu/hw/misc/tpu-ir.h qemu/hw/misc/
	cp src/linux/include/uapi/linux/cord.h linux/include/linux
	cd linux && make -j `nproc`
	strip --strip-debug linux/drivers/misc/tpu/tpu.ko
	cp linux/drivers/misc/tpu/tpu.ko disk/
	$(MAKE) fs

.PHONY:
