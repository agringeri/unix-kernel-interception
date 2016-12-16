// Anthony Gringeri
// acgringeri

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <asm-generic/current.h>
#include <asm-generic/cputime.h>
#include <linux/time.h>
#include <linux/uaccess.h>

// Header file containing struct with include files specific to kernel needs
#include "processinfo_kernel.h"

unsigned long **sys_call_table;

// Pointer to original system call
asmlinkage long (*ref_sys_cs3013_syscall2)(void);

// New call
asmlinkage long new_sys_cs3013_syscall2(struct processinfo *info) { 
    // Main processinfo struct that will store data
    struct processinfo my_processinfo;

    // Capture address of the task_struct of the current process
    struct task_struct *current_process_info = current; // 'current' macro to capture address of current process

	// Initialize all struct values to 0
	my_processinfo.state = 0; //
	my_processinfo.pid = 0; //
	my_processinfo.parent_pid = 0; //
	my_processinfo.youngest_child = 0; //
	my_processinfo.younger_sibling = 0;
	my_processinfo.older_sibling = 0;
	my_processinfo.uid = 0; //
	my_processinfo.start_time = 0; //
	my_processinfo.user_time = 0; //
	my_processinfo.sys_time = 0; //
	my_processinfo.cutime = 0;
	my_processinfo.cstime = 0;

    // Capture data already available in task_struct and copy it to my_processinfo
    my_processinfo.state = current_process_info->state; // current process state
    my_processinfo.pid = current_process_info->pid; // PID of current process (pid_t is signed int)
    my_processinfo.parent_pid = current_process_info->parent->pid; // PID of parent process
	my_processinfo.uid = current_process_info->real_cred->uid.val;

    // Get start time of process and convert to nanoseconds
    my_processinfo.start_time = timespec_to_ns(&current_process_info->start_time); 

	// Get user and system time of process and convert to microseconds
	my_processinfo.user_time = cputime_to_usecs(&current_process_info->utime);
	my_processinfo.sys_time = cputime_to_usecs(&current_process_info->stime);

	// Find pid of youngest child, if there is no children value is -1
	if (list_empty(&current_process_info->children)) {
		my_processinfo.youngest_child = -1; // no children
	} else {
		// get last list entry in children list
		my_processinfo.youngest_child = (list_last_entry(&current_process_info->children, struct task_struct, children))->pid;
	}

	// Find younger sibling of current process, if there is not one, value is -1
	if (list_entry(current_process_info->sibling.next, struct task_struct, sibling)->pid < my_processinfo.pid) {
		my_processinfo.younger_sibling = -1; // no younger sibling
	} else {
		// store pid of younger sibling
		my_processinfo.younger_sibling = (list_entry(current_process_info->sibling.next, struct task_struct, sibling))->pid;
	}

	// Find older sibling of current process, if there is not one, value is -1
	if (list_entry(current_process_info->sibling.prev, struct task_struct, sibling)->pid > my_processinfo.pid) {
		my_processinfo.older_sibling = -1; // no older sibling
	} else {
		// store pid of younger sibling
		my_processinfo.older_sibling = (list_entry(current_process_info->sibling.prev, struct task_struct, sibling))->pid;
	}
		

	if (copy_to_user(info, &my_processinfo, sizeof my_processinfo)) 
		return EFAULT;

    return 0;
}

static unsigned long **find_sys_call_table(void) {
  unsigned long int offset = PAGE_OFFSET;
  unsigned long **sct;
  
  while (offset < ULLONG_MAX) {
    sct = (unsigned long **)offset;

    if (sct[__NR_close] == (unsigned long *) sys_close) {
      printk(KERN_INFO "Interceptor: Found syscall table at address: 0x%02lX",
                (unsigned long) sct);
      return sct;
    }
    
    offset += sizeof(void *);
  }
  
  return NULL;
}

static void disable_page_protection(void) {
  /*
    Control Register 0 (cr0) governs how the CPU operates.

    Bit #16, if set, prevents the CPU from writing to memory marked as
    read only. Well, our system call table meets that description.
    But, we can simply turn off this bit in cr0 to allow us to make
    changes. We read in the current value of the register (32 or 64
    bits wide), and AND that with a value where all bits are 0 except
    the 16th bit (using a negation operation), causing the write_cr0
    value to have the 16th bit cleared (with all other bits staying
    the same. We will thus be able to write to the protected memory.

    It's good to be the kernel!
   */
  write_cr0 (read_cr0 () & (~ 0x10000));
}

static void enable_page_protection(void) {
  /*
   See the above description for cr0. Here, we use an OR to set the 
   16th bit to re-enable write protection on the CPU.
  */
  write_cr0 (read_cr0 () | 0x10000);
}

static int __init interceptor_start(void) {
  /* Find the system call table */
  if(!(sys_call_table = find_sys_call_table())) {
    /* Well, that didn't work. 
       Cancel the module loading step. */
    return -1;
  }
  
  /* Store a copy of all the existing functions */
  ref_sys_cs3013_syscall2 = (void *)sys_call_table[__NR_cs3013_syscall2];

  /* Replace the existing system calls */
  disable_page_protection();

  sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)new_sys_cs3013_syscall2;
  
  enable_page_protection();
  
  /* And indicate the load was successful */
  printk(KERN_INFO "Loaded interceptor!");

  return 0;
}

static void __exit interceptor_end(void) {
  /* If we don't know what the syscall table is, don't bother. */
  if(!sys_call_table)
    return;
  
  /* Revert all system calls to what they were before we began. */
  disable_page_protection();
  sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)ref_sys_cs3013_syscall2;
  enable_page_protection();

  printk(KERN_INFO "Unloaded interceptor!");
}

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);
