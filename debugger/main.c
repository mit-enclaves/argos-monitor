#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

void * dbg_offset = 0;

void* mmap_guest() {
  const char * filepath = "/tmp/tyche";
  int fd = open(filepath, O_RDONLY);
  if (fd < 0) {
    printf("Could not open %s\n", filepath);
    exit(1);
  }
  struct stat statbuf;
  int err = fstat(fd, &statbuf);
  if (err < 0) {
    printf("Unable to fstat the file %s\n", filepath);
    exit(2);
  }
  char *ptr = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED) {
    printf("Mapping Failed %d\n", errno);
    exit(3);
  }
  close(fd);
  return ptr;
}

void gdb_block() {
  for (;;) {}
}
int main(void) {
  dbg_offset = mmap_guest();
  gdb_block();
  return 0;
}
