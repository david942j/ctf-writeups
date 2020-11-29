DISK ?= disk
INIT ?= init

all: kernel user test solution fs

release: kernel user
	$(RM) -r release/disk_clean
	tar xf disk_clean.tar.gz -C release/
	# kernel
	cp linux/arch/x86_64/boot/bzImage release/
	cp linux/drivers/misc/atoms/atoms.ko release/
	cp linux/drivers/misc/atoms/atoms.ko release/disk_clean
	# user
	cp src/user/demo release/
	cp src/user/demo.c release/
	cp src/user/demo release/disk_clean/home/atoms/
	cp src/linux.diff release/
	$(MAKE) DISK=release/disk_clean INIT=init_release fs
	$(RM) -r release/disk_clean
	tar cvfz atoms.tar.gz release/

# depends on "kernel" to ensure kernel compiles
deploy: kernel .PHONY
	sed -i '1 i\#define FLAG "hitcon{kerneldeadlockDoooS}"' linux/kernel/watchdog.c
	$(MAKE) kernel
	sed -i '/^#define FLAG/d' linux/kernel/watchdog.c
	$(RM) -r deploy/disk/
	tar xf disk_clean.tar.gz -C deploy/
	mv deploy/disk_clean deploy/disk
	cp linux/arch/x86_64/boot/bzImage deploy/
	cp linux/drivers/misc/atoms/atoms.ko deploy/disk/
	$(MAKE) DISK=deploy/disk INIT=init_release fs
	$(RM) deploy/initramfs.cpio.gz
	tar cvfz deploy.tar.gz deploy

fs:
	cp src/disk/$(INIT) $(DISK)/init
	cd $(DISK) && find . | cpio -o -Hnewc | gzip -9 > ../initramfs.cpio.gz

test:
	$(MAKE) -C tests
	$(RM) -r disk/tests/
	cp -r tests/ disk/
	$(MAKE) fs

solution:
	$(MAKE) -C sol
	cp sol/exp disk/home/atoms/exp
	$(MAKE) fs

user:
	$(MAKE) -C src/user/
	cp src/user/demo disk/home/atoms/
	$(MAKE) fs

kernel: src/linux/drivers/misc/atoms/* src/linux/include/uapi/linux/atoms.h linux/kernel/watchdog.c
	$(RM) -r linux/drivers/misc/atoms
	cp -r src/linux/drivers/misc/atoms linux/drivers/misc/
	cp src/linux/include/uapi/linux/atoms.h linux/include/uapi/linux
	cd linux && make -j `nproc`
	strip --strip-debug linux/drivers/misc/atoms/atoms.ko
	cp linux/drivers/misc/atoms/atoms.ko disk/
	$(MAKE) fs

# This won't clean linux/
clean: .PHONY
	$(RM) -r deploy/disk/ \
		release/demo* release/initramfs.cpio.gz release/linux.diff \
		src/user/demo \
		tests/test_ioctl
.PHONY:
