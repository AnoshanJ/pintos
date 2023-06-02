#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

// sys_exit is called to terminate the current user program.
void sys_exit (int);

#endif /* userprog/syscall.h */
