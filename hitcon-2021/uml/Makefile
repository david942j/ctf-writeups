all: release

run: .PHONY
	cd release && ./run.sh

release: linux note
	cp linux/linux release/
	cp -f src/note release/fs/
	chmod a-w -R release/fs/*

linux: .PHONY
	$(MAKE) -C linux ARCH=um defconfig
	$(MAKE) -C linux ARCH=um -j`nproc`
	strip -s linux/linux

note: .PHONY
	$(MAKE) -C src

.PHONY:
