#include "ngfw/types.h"
#include <pthread.h>

typedef struct spinlock {
    pthread_spinlock_t lock;
    volatile int locked;
} spinlock_t;

void spinlock_init(void *lock)
{
    pthread_spin_init((pthread_spinlock_t *)lock, PTHREAD_PROCESS_PRIVATE);
}

void spinlock_destroy(void *lock)
{
    pthread_spin_destroy((pthread_spinlock_t *)lock);
}

void spinlock_lock(void *lock)
{
    pthread_spin_lock((pthread_spinlock_t *)lock);
}

void spinlock_unlock(void *lock)
{
    pthread_spin_unlock((pthread_spinlock_t *)lock);
}

bool spinlock_trylock(void *lock)
{
    return pthread_spin_trylock((pthread_spinlock_t *)lock) == 0;
}
