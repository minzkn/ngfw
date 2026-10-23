/* ngfw - platform mutex wrapper (L0). */
#include <pthread.h>
#include <stdlib.h>

#include <ngfw/platform.h>

struct npx_mutex
{
  pthread_mutex_t handle;
};

int
npx_mutex_init (struct npx_mutex **out_mutex)
{
  struct npx_mutex *mutex;

  if (out_mutex == NULL)
    {
      return -1;
    }
  *out_mutex = NULL;
  mutex = (struct npx_mutex *) calloc (1, sizeof (*mutex));
  if (mutex == NULL)
    {
      return -1;
    }
  if (pthread_mutex_init (&mutex->handle, NULL) != 0)
    {
      free (mutex);
      return -1;
    }
  *out_mutex = mutex;
  return 0;
}

void
npx_mutex_lock (struct npx_mutex *mutex)
{
  if (mutex != NULL)
    {
      (void) pthread_mutex_lock (&mutex->handle);
    }
}

void
npx_mutex_unlock (struct npx_mutex *mutex)
{
  if (mutex != NULL)
    {
      (void) pthread_mutex_unlock (&mutex->handle);
    }
}

void
npx_mutex_fini (struct npx_mutex *mutex)
{
  if (mutex != NULL)
    {
      (void) pthread_mutex_destroy (&mutex->handle);
      free (mutex);
    }
}
