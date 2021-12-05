#include <linux/decompress/generic.h>
#include <linux/decompress/inflate.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>

#define FS 0x48000000
#define FS_SIZE 0x3bb80

static int hack_init(void)
{
	u64 *addr;
	int i;

	pr_info("Hacked from kernel!\n");
	addr = phys_to_virt(FS);
	pr_info("%s: %lx\n", __func__, (unsigned long)addr);
	for (i = 0; i < FS_SIZE / sizeof(*addr); i += 16) {
		pr_info("0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n",
			addr[i + 0], addr[i + 1], addr[i + 2], addr[i + 3],
			addr[i + 4], addr[i + 5], addr[i + 6], addr[i + 7],
			addr[i + 8], addr[i + 9], addr[i + 10], addr[i + 11],
			addr[i + 12], addr[i + 13], addr[i + 14], addr[i + 15]
			);
	}
	return 0;
}

static void hack_exit(void)
{
}

module_init(hack_init);
module_exit(hack_exit);

MODULE_DESCRIPTION("meow");
MODULE_LICENSE("GPL");
