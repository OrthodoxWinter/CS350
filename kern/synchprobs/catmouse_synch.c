#include <types.h>
#include <lib.h>
#include <synchprobs.h>
#include <synch.h>

/* 
 * This simple default synchronization mechanism allows only creature at a time to
 * eat.   The globalCatMouseSem is used as a a lock.   We use a semaphore
 * rather than a lock so that this code will work even before locks are implemented.
 */

/* 
 * Replace this default synchronization mechanism with your own (better) mechanism
 * needed for your solution.   Your mechanism may use any of the available synchronzation
 * primitives, e.g., semaphores, locks, condition variables.   You are also free to 
 * declare other global variables if your solution requires them.
 */

/*
 * replace this with declarations of any synchronization and other variables you need here
 */
static struct lock **bowlLocks;

//1=cat 2=mouse 0=switching turn
static volatile int turn;

static volatile int numCreaturesEating;

static struct lock *turnLock;

static struct lock *numCreaturesEatingLock;

static struct cv *noCreatureEating;


/* 
 * The CatMouse simulation will call this function once before any cat or
 * mouse tries to each.
 *
 * You can use it to initialize synchronization and other variables.
 * 
 * parameters: the number of bowls
 */
void
catmouse_sync_init(int bowls)
{
  char lockName[] = "bowl  ";
  bowlLocks = kmalloc(bowls*sizeof(struct lock *));
  KASSERT(bowlLocks != NULL);
  for (int i = 0; i < bowls; i++) {
  	lockName[5] = i + 48;
  	bowlLocks[i] = lock_create(lockName);
  	KASSERT(bowlLocks[i] != NULL);
  }
  turn = -1;
  numCreaturesEating = 0;
  numCreaturesEatingLock = lock_create("numCreaturesEatingLock");
  KASSERT(numCreaturesEatingLock != NULL);
  noCreatureEating = cv_create("noCreatureEating");
  KASSERT(noCreatureEating != NULL);
  turnLock = lock_create("turnLock");
  KASSERT (turnLock != NULL);
  return;
}

/* 
 * The CatMouse simulation will call this function once after all cat
 * and mouse simulations are finished.
 *
 * You can use it to clean up any synchronization and other variables.
 *
 * parameters: the number of bowls
 */
void
catmouse_sync_cleanup(int bowls)
{
  KASSERT(bowlLocks != NULL);
  for (int i = 0; i < bowls; i++) {
  	lock_destroy(bowlLocks[i]);
  }
  kfree(bowlLocks);
  KASSERT(numCreaturesEatingLock != NULL);
  lock_destroy(numCreaturesEatingLock);
  KASSERT(noCreatureEating != NULL);
  cv_destroy(noCreatureEating);
  KASSERT(turnLock != NULL);
  lock_destroy(turnLock);
}


/*
 * The CatMouse simulation will call this function each time a cat wants
 * to eat, before it eats.
 * This function should cause the calling thread (a cat simulation thread)
 * to block until it is OK for a cat to eat at the specified bowl.
 *
 * parameter: the number of the bowl at which the cat is trying to eat
 *             legal bowl numbers are 1..NumBowls
 *
 * return value: none
 */

void
cat_before_eating(unsigned int bowl) 
{
  /*
  if changing turn then
    wait unil switching is complete
  */
  lock_acquire(bowlLocks[bowl - 1]);
  lock_acquire(turnLock);
  lock_acquire(numCreaturesEatingLock);
  if (turn == -1) {
  	turn = 1;
  } else if (turn == 2) {
  	while (numCreaturesEating > 0) {
  		cv_wait(noCreatureEating, numCreaturesEatingLock);
  	}
  	KASSERT(numCreaturesEating == 0);
  	turn = 1;
  }
  KASSERT(turn == 1);
  numCreaturesEating++;
  lock_release(numCreaturesEatingLock);
  lock_release(turnLock);
}

/*
 * The CatMouse simulation will call this function each time a cat finishes
 * eating.
 *
 * You can use this function to wake up other creatures that may have been
 * waiting to eat until this cat finished.
 *
 * parameter: the number of the bowl at which the cat is finishing eating.
 *             legal bowl numbers are 1..NumBowls
 *
 * return value: none
 */

void
cat_after_eating(unsigned int bowl) 
{
  KASSERT(bowlLocks != NULL);
  KASSERT(numCreaturesEatingLock != NULL);
  lock_acquire(numCreaturesEatingLock);
  numCreaturesEating--;
  if (numCreaturesEating == 0) {
  	cv_broadcast(noCreatureEating, numCreaturesEatingLock);
  }
  lock_release(numCreaturesEatingLock);
  lock_release(bowlLocks[bowl - 1]);
}

/*
 * The CatMouse simulation will call this function each time a mouse wants
 * to eat, before it eats.
 * This function should cause the calling thread (a mouse simulation thread)
 * to block until it is OK for a mouse to eat at the specified bowl.
 *
 * parameter: the number of the bowl at which the mouse is trying to eat
 *             legal bowl numbers are 1..NumBowls
 *
 * return value: none
 */

void
mouse_before_eating(unsigned int bowl) 
{
  lock_acquire(bowlLocks[bowl - 1]);
  lock_acquire(turnLock);
  lock_acquire(numCreaturesEatingLock);
  if (turn == -1) {
  	turn = 2;
  } else if (turn == 1) {
  	while (numCreaturesEating > 0) {
  		cv_wait(noCreatureEating, numCreaturesEatingLock);
  	}
  	KASSERT(numCreaturesEating == 0);
  	turn = 2;
  }
  KASSERT(turn == 2);
  numCreaturesEating++;
  lock_release(numCreaturesEatingLock);
  lock_release(turnLock);
}

/*
 * The CatMouse simulation will call this function each time a mouse finishes
 * eating.
 *
 * You can use this function to wake up other creatures that may have been
 * waiting to eat until this mouse finished.
 *
 * parameter: the number of the bowl at which the mouse is finishing eating.
 *             legal bowl numbers are 1..NumBowls
 *
 * return value: none
 */

void
mouse_after_eating(unsigned int bowl) 
{
  KASSERT(bowlLocks != NULL);
  KASSERT(numCreaturesEatingLock != NULL);
  lock_acquire(numCreaturesEatingLock);
  numCreaturesEating--;
  if (numCreaturesEating == 0) {
  	cv_broadcast(noCreatureEating, numCreaturesEatingLock);
  }
  lock_release(numCreaturesEatingLock);
  lock_release(bowlLocks[bowl - 1]);
}
