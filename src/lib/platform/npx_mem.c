/* ngfw - platform memory wrappers (L0). */
#include <stdlib.h>
#include <string.h>

#include <ngfw/platform.h>

void *
npx_malloc (size_t size)
{
  if (size == 0)
    {
      size = 1;
    }
  return malloc (size);
}

void *
npx_calloc (size_t nmemb, size_t size)
{
  if (nmemb == 0 || size == 0)
    {
      nmemb = 1;
      size = 1;
    }
  return calloc (nmemb, size);
}

void *
npx_realloc (void *ptr, size_t size)
{
  if (size == 0)
    {
      npx_free (ptr);
      return npx_malloc (0);
    }
  return realloc (ptr, size);
}

void
npx_free (void *ptr)
{
  free (ptr);
}

char *
npx_strdup (const char *text)
{
  size_t length;
  char *copy;

  if (text == NULL)
    {
      return NULL;
    }
  length = strlen (text);
  copy = (char *) npx_malloc (length + 1);
  if (copy == NULL)
    {
      return NULL;
    }
  memcpy (copy, text, length + 1);
  return copy;
}
