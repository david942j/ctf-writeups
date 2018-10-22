#ifndef SYS_EXIT_H
#define SYS_EXIT_H

void sys_exit_group(int status);

/* alias */
#define sys_exit sys_exit_group

#endif
