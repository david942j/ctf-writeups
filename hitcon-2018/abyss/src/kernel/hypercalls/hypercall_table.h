#ifndef HYPERCALL_TABLE_H
#define HYPERCALL_TABLE_H

#define HP_NR_MARK 0x8000

#define NR_HP_open  (HP_NR_MARK | 0)
#define NR_HP_read  (HP_NR_MARK | 1)
#define NR_HP_write  (HP_NR_MARK | 2)
#define NR_HP_lseek  (HP_NR_MARK | 3)
#define NR_HP_close  (HP_NR_MARK | 4)
#define NR_HP_fstat  (HP_NR_MARK | 5)
#define NR_HP_exit  (HP_NR_MARK | 6)
#define NR_HP_access (HP_NR_MARK | 7)
#define NR_HP_ioctl (HP_NR_MARK | 8)

#define NR_HP_panic (HP_NR_MARK | 0x7fff)

#endif
