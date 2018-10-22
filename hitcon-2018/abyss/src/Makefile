DIRS := user hypervisor kernel

all: $(DIRS)

$(DIRS): FORCE
	$(MAKE) -C $@

debug:
	echo $(DIRS) | xargs -n 1 $(MAKE) KVM_DEBUG=1 -C

# test: all
	# hypervisor/hypervisor.elf kernel/kernel.bin /lib64/ld-linux-x86-64.so.2 /bin/cat /etc/os-release

release: all
	cp hypervisor/hypervisor.elf ../release
	cp kernel/kernel.bin ../release
	cp user/user.elf ../release
	cp /lib64/ld-linux-x86-64.so.2 ../release/ld.so.2
	cp /lib/x86_64-linux-gnu/libc.so.6 ../release/libc.so.6

clean:
	echo $(DIRS) | xargs -n 1 $(MAKE) clean -C
FORCE:
