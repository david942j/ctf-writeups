FLAG ?= <FLAG WILL BE HERE>
DISK ?= disk
INIT ?= init

all: kernel user test solution fs

release: kernel user
	$(RM) -r release/disk_clean
	tar xf disk_clean.tar.gz -C release/
	# kernel
	cp linux/arch/x86_64/boot/bzImage release/
	cp linux/drivers/misc/spark/spark.ko release/
	cp linux/drivers/misc/spark/spark.ko release/disk_clean
	# user
	cp src/user/demo release/
	cp src/user/demo.c release/
	cp src/user/demo release/disk_clean/home/spark/
	$(MAKE) DISK=release/disk_clean INIT=init_release fs
	$(RM) -r release/disk_clean
	tar cvfz spark.tar.gz release/

deploy: .PHONY
	$(MAKE) 'FLAG=<FLAG WILL BE HERE>' release
	$(RM) -r deploy/disk/
	tar xf disk_clean.tar.gz -C deploy/
	mv deploy/disk_clean deploy/disk
	cp release/bzImage deploy/
	cp release/spark.ko deploy/disk/
	$(MAKE) FLAG='hitcon{easy_graph_theory_easy_kernel_exploitation}' DISK=deploy/disk INIT=init_release fs
	$(RM) deploy/initramfs.cpio.gz
	tar cvfz deploy.tar.gz deploy

fs:
	echo "$(FLAG)" > $(DISK)/flag
	cp src/disk/$(INIT) $(DISK)/init
	cd $(DISK) && find . | cpio -o -Hnewc | gzip -9 > ../initramfs.cpio.gz

test:
	$(MAKE) -C tests
	$(RM) -r disk/tests/
	cp -r tests/ disk/
	$(MAKE) fs

solution:
	$(MAKE) -C sol
	cp sol/exp disk/home/spark/exp
	$(MAKE) fs

user:
	$(MAKE) -C src/user/
	cp src/user/demo disk/home/spark/
	$(MAKE) fs

kernel: src/linux/drivers/misc/spark/* src/linux/include/uapi/linux/spark.h
	$(RM) -r linux/drivers/misc/spark
	cp -r src/linux/drivers/misc/spark linux/drivers/misc/
	cp src/linux/include/uapi/linux/spark.h linux/include/uapi/linux
	cd linux && make -j `nproc`
	strip --strip-debug linux/drivers/misc/spark/spark.ko
	cp linux/drivers/misc/spark/spark.ko disk/
	$(MAKE) fs

# This won't clean linux/
clean: .PHONY
	$(RM) -r deploy/disk/ \
		release/demo* release/initramfs.cpio.gz \
		src/user/demo \
		tests/test_ioctl
.PHONY:
