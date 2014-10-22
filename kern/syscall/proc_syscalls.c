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

  /* this implementation of sys__exit does not do anything with the exit code */
  /* this needs to be fixed to get exit() and waitpid() working properly */

void sys__exit(int exitcode) {

  struct addrspace *as;
  struct proc *p = curproc;
  /* for now, just include this to keep the compiler from complaining about
     an unused variable */
  (void)exitcode;

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

  //acquire proctable_lock
  struct proc_info *info = get_proc_info(p->pid);
  if (p->forked_child == 0 && info->parent_pid == 0) {
    free_pid(p->pid);
  } else if (p->forked_child == 1) {
    //has children
    for (int i = 0 i < proctable->num; i++) {
      struct proc_info *t = proctable->v[i];
      if (t->parent_pid == p->pid) {
        //t is a child of p
        if (t->exited == 1) {
          kfree(t);
          proctable->v[i] = NULL;
        } else {
          t->parent_pid == 0;
        }
      }
    }
    if (p->parent_pid == 0) {
      free_pid(p->pid);
    } else {
      info->exited = 1;
      info->exit_code = exitcode;
    }
  } else {
    //has parent and no child
    info->exited = 1;
    info->exit_code = exitcode;
  }
  //release proctable_lock

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
  *retval = 1;
  return(0);
}

/* stub handler for waitpid() system call                */

int
sys_waitpid(pid_t pid,
	    userptr_t status,
	    int options,
	    pid_t *retval)
{
  int exitstatus;
  int result;

  /* this is just a stub implementation that always reports an
     exit status of 0, regardless of the actual exit status of
     the specified process.   
     In fact, this will return 0 even if the specified process
     is still running, and even if it never existed in the first place.

     Fix this!
  */

  if (options != 0) {
    return(EINVAL);
  }
  /* for now, just pretend the exitstatus is 0 */
  exitstatus = 0;
  result = copyout((void *)&exitstatus,status,sizeof(int));
  if (result) {
    return(result);
  }
  *retval = pid;
  return(0);
}

int
sys_fork(struct trapframe *tf, pid_t *retval) {
  //kprintf("sys_fork called\n");
  //Acquire the curent proc
  spinlock_acquire(&curproc->p_lock);
  //get a copy of the current proc's address space
  struct addrspace *copyAddrspace;
  as_copy(curproc->p_addrspace, &copyAddrspace);
  //create a new child proc
  struct proc *childProc = proc_create_runprogram(curproc->p_name);
  spinlock_release(&curproc->p_lock);
  childProc->p_addrspace = copyAddrspace;
  //struct semaphore *mutex = sem_create("fork mutex",0);
  lock_acquire(fork_lock);
  thread_fork(curthread->t_name, childProc, dupProc, tf, 0);
  //wait until the new proc finishes copying the trapframe and addrspace, then return the pid of the child proc
  P(fork_mutex);
  lock_release(fork_lock);
  *retval = 1;
  return 0;
}

void dupProc(void *temp, unsigned long unused) {
  (void) unused;
  struct trapframe tf = * (struct trapframe*) temp;
  tf.tf_v0 = 0;
  tf.tf_epc += 4;
  as_activate();
  V(fork_mutex);
  enter_forked_process(&tf);
}

