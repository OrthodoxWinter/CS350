#include <types.h>
#include <kern/errno.h>
#include <kern/unistd.h>
#include <kern/wait.h>
#include <lib.h>
#include <syscall.h>
#include <current.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <copyinout.h>
#include <synch.h>
#include <mips/trapframe.h>
#include <vfs.h>
#include <kern/fcntl.h>
#include <limits.h>

  /* this implementation of sys__exit does not do anything with the exit code */
  /* this needs to be fixed to get exit() and waitpid() working properly */

void sys__exit(int exitcode) {

  struct addrspace *as;
  struct proc *p = curproc;
  /* for now, just include this to keep the compiler from complaining about
     an unused variable */

  DEBUG(DB_SYSCALL,"Syscall: _exit(%d)\n",exitcode);

  KASSERT(curproc->p_addrspace != NULL);
  as_deactivate();
  /*
   * clear p_addrspace before calling as_destroy. Otherwise if
   * as_destroy sleeps (which is quite possible) when we
   * come back we'll be calling as_activate on a
   * half-destroyed address space. This tends to be
   * messily fatal.
   */
  as = curproc_setas(NULL);
  as_destroy(as);

  /* detach this thread from its process */
  /* note: curproc cannot be used after this call */
  proc_remthread(curthread);


  //kprintf("called sys_exit on proc with pid: %d\n", (int) p->pid);
  lock_acquire(proctable_lock);
  struct proc_info *info = get_proc_info(p->pid);
  if (p->forked_child == 0 && info->parent_pid == 0) {
    free_pid(p->pid);
  } else if (p->forked_child == 1) {
    //has children
    for (unsigned int i = 0; i < proc_table_num(proctable); i++) {
      struct proc_info *t = proc_table_get(proctable, i);
      if (t->parent_pid == p->pid) {
        //t is a child of p
        if (t->exited == 1) {
          t->pid_free = 1;
          t->parent_pid = 0;
          t->exit_code = 0;
          t->exited = -1;
        } else {
          t->parent_pid = 0;
        }
      }
    }
    if (info->parent_pid == 0) {
      //kprintf("pid %d has child but no parent", (int) p->pid);
      free_pid(p->pid);
    } else {
      info->exited = 1;
      info->exit_code = exitcode;
      cv_broadcast(info->proc_exit, proctable_lock);
    }
  } else {
    //has parent and no child
    //kprintf("pid %d has parent but no child", (int) p->pid);
    info->exited = 1;
    info->exit_code = exitcode;
    cv_broadcast(info->proc_exit, proctable_lock);
  }
  lock_release(proctable_lock);
  
  

  /* if this is the last user process in the system, proc_destroy()
     will wake up the kernel menu thread */
  proc_destroy(p);
  
  thread_exit();
  /* thread_exit() does not return, so we should never get here */
  panic("return from thread_exit in sys_exit\n");
}


/* stub handler for getpid() system call                */
int
sys_getpid(pid_t *retval)
{
  /* for now, this is just a stub that always returns a PID of 1 */
  /* you need to fix this to make it work properly */
  spinlock_acquire(&curproc->p_lock);
  *retval = curproc->pid;
  spinlock_release(&curproc->p_lock);
  return(0);
}

/* stub handler for waitpid() system call                */

int
sys_waitpid(pid_t pid,
	    userptr_t status,
	    int options,
	    pid_t *retval)
{
  //kprintf("waitpid called on pid %d\n", (int) pid);
  int exitstatus = 0;
  int result = 0;

  if (options != 0) {
    return(EINVAL);
  }
  spinlock_acquire(&curproc->p_lock);
  pid_t current_pid = curproc->pid;
  spinlock_release(&curproc->p_lock);
  
  lock_acquire(proctable_lock);
  //kprintf("getting proc info for pid %d\n", (int) pid);
  struct proc_info* info = get_proc_info(pid);
  if (info == NULL || info->pid_free == 1) {
    //kprintf("ESRCH\n");
    lock_release(proctable_lock);
    return ESRCH;
  }
  if (info->parent_pid != current_pid) {
    lock_release(proctable_lock);
    return ECHILD;
  } else {
    if (info->exited == 1) {
      exitstatus = _MKWVAL(info->exit_code);
      result = copyout((void *)&exitstatus,status,sizeof(int));
    } else {
      while (info->exited == 0) {
        cv_wait(info->proc_exit, proctable_lock);
      }
      exitstatus = _MKWVAL(info->exit_code);
      result = copyout((void *)&exitstatus,status,sizeof(int));
    }
  }
  lock_release(proctable_lock);
  *retval = pid;
  return result;
}

int
sys_fork(struct trapframe *tf, pid_t *retval) {
  //kprintf("sys_fork called\n");

  struct addrspace* copyAddrspace;
  //Acquire the curent proc
  spinlock_acquire(&curproc->p_lock);
  int copy_success = as_copy(curproc->p_addrspace, &copyAddrspace);
  char* curproc_name = curproc->p_name;
  pid_t curproc_pid = curproc->pid;
  spinlock_release(&curproc->p_lock);
  //get a copy of the current proc's address space
  
  if (copy_success != 0) {
    return ENOMEM;
  }
  //create a new child proc
  struct proc *childProc = proc_create_runprogram(curproc_name);
  if (childProc == NULL) {
    as_destroy(copyAddrspace);
    return ENPROC;
  }
  lock_acquire(proctable_lock);
  struct proc_info* info = get_proc_info(childProc->pid);
  info->parent_pid = curproc_pid;
  lock_release(proctable_lock);

  spinlock_acquire(&curproc->p_lock);
  curproc->forked_child = 1;
  spinlock_release(&curproc->p_lock);

  childProc->p_addrspace = copyAddrspace;
  
  struct trapframe* temp = kmalloc(sizeof(struct trapframe));
  memcpy(temp, tf, sizeof(struct trapframe));

  thread_fork(curthread->t_name, childProc, dupProc, temp, 0);
  //wait until the new proc finishes copying the trapframe and addrspace, then return the pid of the child proc
  *retval = childProc->pid;
  return 0;
}

void dupProc(void *temp, unsigned long unused) {
  (void) unused;
  struct trapframe tf = * (struct trapframe*) temp;
  kfree(temp);
  tf.tf_v0 = 0;
  tf.tf_epc += 4;
  as_activate();
  enter_forked_process(&tf);
}

int sys_execv(userptr_t progname, userptr_t* args) {
  struct addrspace* as;
  struct vnode* v;
  vaddr_t entrypoint, stackptr;
  int result;

  size_t progname_len = 0;
  char* new_progname = kmalloc(NAME_MAX*sizeof(char));
  copyinstr(progname, new_progname, NAME_MAX, &progname_len);

  int num_args = 0;

  while (args[num_args] != NULL) {
    num_args++;
  }
  //kprintf("num_args: %d\n", num_args);

  char** new_args = kmalloc((num_args + 1) * sizeof(char*));
  size_t args_str_len[num_args];

  int i = 0;
  for (i = 0; i < num_args; i++) {
    new_args[i] = kmalloc(1024 * sizeof(char));
    copyinstr(args[i], new_args[i], 1024, (args_str_len+i));
    //kprintf(new_args[i]);
  }
  new_args[i] = NULL;

  result = vfs_open(new_progname, O_RDONLY, 0, &v);
  if (result) {
    return result;
  }

  as = as_create();
  if (as ==NULL) {
    vfs_close(v);
    return ENOMEM;
  }

  as_deactivate();

  /* Switch to it and activate it. */
  struct addrspace* oldas = curproc_setas(as);
  
  as_destroy(oldas);

  as_activate();

  /* Load the executable. */
  result = load_elf(v, &entrypoint);
  if (result) {
    /* p_addrspace will go away when curproc is destroyed */
    vfs_close(v);
    return result;
  }

  /* Done with the file now. */
  vfs_close(v);

  /* Define the user stack in the address space */
  result = as_define_stack(as, &stackptr);

  if (result) {
    /* p_addrspace will go away when curproc is destroyed */
    return result;
  }

  size_t total_args_size = 0;

  for (int i = 0; i < num_args; i++) {
    total_args_size+= args_str_len[i];
  }

  total_args_size = ROUNDUP(total_args_size, 8);

  //kprintf("stackptr: %u\n", (unsigned int) stackptr);
  //kprintf("total_args_size: %u\n", (unsigned int) total_args_size);

  userptr_t args_str_addr = (userptr_t) stackptr - total_args_size;
  //kprintf("args_str_addr: %u\n", (unsigned int) args_str_addr);

  size_t args_array_size = ROUNDUP(4*(num_args + 1), 8);
  //kprintf("args_array_size: %u\n", (unsigned int) args_array_size);

  userptr_t args_array_addr = (userptr_t) args_str_addr - args_array_size;
  vaddr_t new_stack_ptr = (vaddr_t) args_array_addr;
  //kprintf("args_array_addr: %u\n", (unsigned int) args_array_addr);

  for (int i = 0; i < num_args; i++) {
    size_t length = 0;
    copyoutstr(new_args[i], args_str_addr, 1024, &length);
    KASSERT(length == args_str_len[i]);
    copyout((void*) &args_str_addr, args_array_addr, 4);
    args_array_addr += 4;
    args_str_addr += length;
  }

  void* empty = NULL;
  copyout(empty, (userptr_t) args_array_addr, 4);

  kfree(new_progname);

  for (int i = 0; i < num_args; i++) {
    kfree(new_args[i]);
  }
  kfree(new_args);

  /* Warp to user mode. */
  enter_new_process(num_args /*argc*/, (userptr_t) new_stack_ptr /*userspace addr of argv*/,
        new_stack_ptr, entrypoint);
  
  /* enter_new_process does not return. */
  panic("enter_new_process returned\n");
  return EINVAL;
}


