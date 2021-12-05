KERNEL_DIR = ../linux
all: run

remote: dtb
	./send.rb r

run: dtb
	./run.sh

hack.dts: fs
	./gen.rb

dtb: hack.dts
	dtc -I dts -O dtb hack.dts -o hack.dtb

module: .PHONY
	$(MAKE) -C $(KERNEL_DIR) ARCH=arm64 LLVM=1 CROSS_COMPILE=aarch64-linux-gnu- M=$(PWD)/module src.ko
	strip --strip-unneeded module/src.ko

fs: module
	cp module/src.ko fs_fake/
	./init.py fs_fake/init
	chmod +x fs_fake/init
	cd fs_fake && find . | cpio -o -Hnewc | gzip -9 > ../fakefs.cpio.gz && cd ..

.PHONY:
