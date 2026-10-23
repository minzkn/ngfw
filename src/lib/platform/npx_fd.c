/* ngfw - platform descriptor I/O wrappers (L0). */
#include <unistd.h>

#include <ngfw/platform.h>

int
npx_fd_read (int fd, void *buffer, size_t length)
{
  ssize_t done;

  if (fd < 0 || buffer == NULL || length == 0)
    {
      return -1;
    }
  done = read (fd, buffer, length);
  return (done < 0) ? -1 : (int) done;
}

int
npx_fd_write (int fd, const void *data, size_t length)
{
  ssize_t done;

  if (fd < 0 || data == NULL || length == 0)
    {
      return -1;
    }
  done = write (fd, data, length);
  return (done < 0) ? -1 : (int) done;
}

int
npx_fd_close (int fd)
{
  if (fd < 0)
    {
      return -1;
    }
  return (close (fd) == 0) ? 0 : -1;
}
