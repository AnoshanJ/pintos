#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"

// #define DEBUG
#ifdef DEBUG
#define _DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define _DEBUG_PRINTF(...)
#endif

static void syscall_handler (struct intr_frame *);

static bool put_user (uint8_t *udst, uint8_t byte);
static int user_memread (void *src, void *des, size_t bytes);
static void check_user (const uint8_t *uaddr);
static int32_t get_user (const uint8_t *uaddr);


/* File System Lock */
struct lock filesys_lock;

/* Find File Descriptor */
static struct file_desc* find_file_desc(struct thread *, int fd);

/* Execute Command */
pid_t sys_exec (const char *cmdline);

/* Halt System */
void s_halt (void);

/* Exit System */
void sys_exit (int);

/* Wait for Process */
int s_wait (pid_t pid);

/* Create File */
bool s_create(const char* filename, unsigned initial_size);

/* Remove File */
bool s_remove(const char* filename);

/* Open File */
int s_open(const char* file);

/* Get File Size */
int s_filesize(int fd);

/* Set File Position */
void s_seek(int fd, unsigned position);

/* Get File Position */
unsigned s_tell(int fd);

/* Close File */
void s_close(int fd);

/* Read from File */
int s_read(int fd, void *buffer, unsigned size);

/* Write to File */
int s_write(int fd, const void *buffer, unsigned size);


void
syscall_init (void)
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void
syscall_handler (struct intr_frame *f)
{
  int syscall_num;

  ASSERT( sizeof(syscall_num) == 4 ); // assuming x86

  user_memread(f->esp, &syscall_num, sizeof(syscall_num));

  _DEBUG_PRINTF ("[DEBUG] system call, number = %d!\n", syscall_num);

  switch (syscall_num) {
  case SYS_HALT:
  {
    /* Handle system call with number 0 */
    s_halt();
    NOT_REACHED();
    break;
  }
  case SYS_EXIT:
  {
    /* Handle system call with number 1 */
    int exitcode;
    user_memread(f->esp + 4, &exitcode, sizeof(exitcode));
    sys_exit(exitcode);
    NOT_REACHED();
    break;
  }
  case SYS_EXEC:
    { 
      /*Handle system call with number 2*/
      void* cmd_line;
      user_memread(f->esp + 4, &cmd_line, sizeof(cmd_line));

      int return_code = sys_exec((const char*) cmd_line);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WAIT:
    { 
      /*Handle system call with number 3*/
      pid_t pid;
      user_memread(f->esp + 4, &pid, sizeof(pid_t));

      int ret = s_wait(pid);
      f->eax = (uint32_t) ret;
      break;
    }

  case SYS_CREATE:
    { /*Handle system call with number 4*/
      const char* file_name;
      unsigned initial_size;
      bool return_code;

      user_memread(f->esp + 4, &file_name, sizeof(file_name));
      user_memread(f->esp + 8, &initial_size, sizeof(initial_size));

      return_code = s_create(file_name, initial_size);
      f->eax = return_code;
      break;
    }

  case SYS_REMOVE:
    { 
      /*Handle system call with number 5*/
      const char* filename;
      bool return_code;

      user_memread(f->esp + 4, &filename, sizeof(filename));

      return_code = s_remove(filename);
      f->eax = return_code;
      break;
    }

  case SYS_OPEN: 
    { 
      /*Handle system call with number 6*/
      const char* file_name;
      int return_code;
      // memory read from user space
      user_memread(f->esp + 4, &file_name, sizeof(file_name));

      return_code = s_open(file_name);
      f->eax = return_code;
      break;
    }

  case SYS_FILESIZE: 
    { 
      /*Handle system call with number 7*/
      int fd, return_code;
      // memory read from user space
      user_memread(f->esp + 4, &fd, sizeof(fd));

      return_code = s_filesize(fd);
      f->eax = return_code;
      break;
    }

  case SYS_READ:
    { /*Handle system call with number 8*/
      int fd, return_code;
      void *buffer;
      unsigned size;

      user_memread(f->esp + 4, &fd, sizeof(fd));
      user_memread(f->esp + 8, &buffer, sizeof(buffer));
      user_memread(f->esp + 12, &size, sizeof(size));

      return_code = s_read(fd, buffer, size);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WRITE: 
    { /*Handle system call with number 9*/
      int fd, return_code;
      const void *buffer;
      unsigned size;

      user_memread(f->esp + 4, &fd, sizeof(fd));
      user_memread(f->esp + 8, &buffer, sizeof(buffer));
      user_memread(f->esp + 12, &size, sizeof(size));

      return_code = s_write(fd, buffer, size);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_SEEK: 
    { /*Handle system call with number 10*/
      int fd;
      unsigned position;

      user_memread(f->esp + 4, &fd, sizeof(fd));
      user_memread(f->esp + 8, &position, sizeof(position));

      s_seek(fd, position);
      break;
    }

  case SYS_TELL: 
    { /*Handle system call with number 11*/
      int fd;
      unsigned return_code;

      user_memread(f->esp + 4, &fd, sizeof(fd));

      return_code = s_tell(fd);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_CLOSE:
    { /*Handle system call with number 12*/
      int fd;
      user_memread(f->esp + 4, &fd, sizeof(fd));

      s_close(fd);
      break;
    }


  /* Handling unhandled system call */
  default:
    printf("[ERROR] system call %d is unimplemented!\n", syscall_num);
    sys_exit(-1);
    break;

  }

}

/****************** System Call Implementations ********************/

void s_halt(void) {
  shutdown_power_off();
}

pid_t sys_exec(const char *cmd_line) {
/* Print debugging information */
_DEBUG_PRINTF ("[DEBUG] Executing: %s\n", cmd_line);

/* Check if cmdline is a valid address in user memory */
check_user((const uint8_t*) cmd_line);

/* Acquire lock before accessing the file system */
lock_acquire (&filesys_lock);

/* Execute the process */
pid_t pid = process_execute(cmd_line);

/* Release lock after accessing the file system */
lock_release (&filesys_lock);

/* Return the process id */
return pid;
}

void sys_exit(int status) {
/* Print process name and exit status */
printf("%s: exit(%d)\n", thread_current()->name, status);

/* Get the process control block */
struct process_control_block *pcb = thread_current()->pcb;

/* If process control block exists, set exit status */
if(pcb != NULL) {
pcb->exited = true;
pcb->exitcode = status;
} else {
/* If process control block does not exist, it means
allocation of pages failed in process_execute() */
}

/* Exit the process */
thread_exit();
}
// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) {
  if (lock_held_by_current_thread(&filesys_lock))
    lock_release (&filesys_lock);

  sys_exit (-1);
  NOT_REACHED();
}

/* sys_wait function
   waits for the process with specified PID to exit */
int s_wait(pid_t pid) {
  // Debug message
  _DEBUG_PRINTF ("[DEBUG] Wait : %d\n", pid);

  // wait for process with PID to exit
  return process_wait(pid);
}

/* sys_create function
   creates a file with specified name and initial size */
bool s_create(const char* file_name, unsigned initial_size) {
  bool return_code;

  // Validate user memory
  check_user((const uint8_t*) file_name);

  // Acquire file system lock
  lock_acquire (&filesys_lock);
  
  // create the file
  return_code = filesys_create(file_name, initial_size);

  // Release file system lock
  lock_release (&filesys_lock);
  return return_code;
}

/* sys_remove function
   removes a file with specified name */
bool s_remove(const char* filename) {
  bool return_code;

  // Validate user memory
  check_user((const uint8_t*) filename);

  // Acquire file system lock
  lock_acquire (&filesys_lock);

  // remove the file
  return_code = filesys_remove(filename);

  // Release file system lock
  lock_release (&filesys_lock);
  return return_code;
}


int s_open(const char* file) {
  // memory validation
  check_user((const uint8_t*) file);

  struct file* file_opened;
  struct file_desc* fd = palloc_get_page(0);
  if (!fd) {
    return -1;
  }

  lock_acquire (&filesys_lock);
  file_opened = filesys_open(file);
  if (!file_opened) {
    palloc_free_page (fd);
    lock_release (&filesys_lock);
    return -1;
  }

  fd->file = file_opened; //file save

  struct list* fd_list = &thread_current()->file_descriptors;
  if (list_empty(fd_list)) {
    // 0, 1, 2 are reserved for stdin, stdout, stderr
    fd->id = 3;
  }
  else {
    fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  lock_release (&filesys_lock);
  return fd->id;
}

int s_filesize(int fd) {
  struct file_desc* file_d;

  lock_acquire (&filesys_lock);
  file_d = find_file_desc(thread_current(), fd);

  if(file_d == NULL) {
    lock_release (&filesys_lock);
    return -1;
  }

  int ret = file_length(file_d->file);
  lock_release (&filesys_lock);
  return ret;
}


unsigned s_tell(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd);

  unsigned ret;
  if(file_d && file_d->file) {
    ret = file_tell(file_d->file);
  }
  else
    ret = -1; // TODO need sys_exit?

  lock_release (&filesys_lock);
  return ret;
}

void s_seek(int fd, unsigned position) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    file_seek(file_d->file, position);
  }
  else
    return; // TODO need sys_exit?

  lock_release (&filesys_lock);
}
void s_close(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    file_close(file_d->file);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
  lock_release (&filesys_lock);
}


int s_write(int fd, const void *buffer, unsigned size) {
  // memory validation : [buffer+0, buffer+size) should be all valid
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == 1) { // write to stdout
    putbuf(buffer, size);
    ret = size;
  }
  else {
    // write into file
    struct file_desc* file_d = find_file_desc(thread_current(), fd);

    if(file_d && file_d->file) {
      ret = file_write(file_d->file, buffer, size);
    }
    else // no such file or can't open
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}
// Function to read from a file or standard input
int s_read(int fd, void *buffer, unsigned size) {
  // Check if the memory range [buffer, buffer + size) is valid
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  // Acquire lock to access file system
  lock_acquire(&filesys_lock);

  int ret;

  // If reading from standard input (fd = 0)
  if (fd == 0) {
    // Loop to fill the buffer with input from user
    for (unsigned i = 0; i < size; ++i) {
      if (!put_user(buffer + i, input_getc())) {
        // Release lock and exit if a segfault occurs
        lock_release(&filesys_lock);
        sys_exit(-1);
      }
    }
    ret = size;
  } else {
    // Find the file descriptor for the given file
    struct file_desc* file_d = find_file_desc(thread_current(), fd);

    // If the file exists and can be opened
    if (file_d && file_d->file) {
      // Read from the file
      ret = file_read(file_d->file, buffer, size);
    } else {
      // Return -1 if the file does not exist or cannot be opened
      ret = -1;
    }
  }

  // Release lock after reading from the file
  lock_release(&filesys_lock);

  return ret;
}

/**************** Helper Functions for Memory Access ******************/

static void
check_user (const uint8_t *uaddr) {
  // check uaddr range or segfaults
  if(get_user (uaddr) == -1)
    fail_invalid_access();
}
/**
Reads a single byte from user memory at 'uaddr' and
returns the byte value if successful (least significant byte) or -1 on error (segfault or invalid uaddr).
*/
static int32_t get_user(const uint8_t *uaddr) {
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }
int result;
 asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
return result;
}

/**
Writes a single byte to user address 'udst' and returns true on success, false on segfault.
*/
static bool put_user(uint8_t *udst, uint8_t byte) {
  if (! ((void*)udst < PHYS_BASE)) {
    return false;
  }
int error_code;
asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
return error_code != -1;
}

/**
Reads bytes of user memory at 'src' and writes to 'dst' and returns the number of bytes read. 
Exits on invalid access with return code -1.
*/
static int user_memread(void *src, void *dst, size_t bytes) {
int32_t value;
for (size_t i = 0; i < bytes; i++) {
value = get_user(src + i);
if (value == -1) {
fail_invalid_access();
}

*(char *)(dst + i) = value & 0xff;
}
return (int)bytes;
}

/**
Finds file descriptor with ID 'fd' in the thread 't' and returns it.
*/
static struct file_desc *find_file_desc(struct thread *t, int fd) {
ASSERT (t != NULL);
if (fd < 3) {
return NULL;
}

  struct list_elem *e;

  if (! list_empty(&t->file_descriptors)) {
    for(e = list_begin(&t->file_descriptors);
        e != list_end(&t->file_descriptors); e = list_next(e))
    {
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
        return desc;
      }
    }
  }

  return NULL; // not found
}