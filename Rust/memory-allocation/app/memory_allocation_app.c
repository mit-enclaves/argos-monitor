#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

#define DRIVER_NAME "/dev/memory_allocation"

int open_driver(const char* driver_name);
void close_driver(const char* driver_name, int fd_driver);

int open_driver(const char* driver_name) {

    	printf("Open Driver\n");

    	int fd_driver = open(driver_name, O_RDWR);
    	if (fd_driver == -1) {
        	printf("ERROR: could not open \"%s\".\n", driver_name);
        	printf("    errno = %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}

	return fd_driver;
}

void close_driver(const char* driver_name, int fd_driver) {

    	printf("Close Driver\n");

    	int result = close(fd_driver);
    	if (result == -1) {
        	printf("ERROR: could not close \"%s\".\n", driver_name);
        	printf("    errno = %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}
}

int main(int argc, const char* argv) {
	int fd = open_driver(DRIVER_NAME);

	printf("page size: %zu\n", sysconf(_SC_PAGESIZE));

	char *m = (char*) mmap(
			NULL, 
			sysconf(_SC_PAGESIZE), 
			PROT_READ, 
			MAP_SHARED, 
			fd, 
			0);

	if (m == MAP_FAILED) {
		perror("Error mapping failed");
		exit(EXIT_FAILURE);
	}

	printf("page mapped at: %p\nfirst bytes:\n", m);
	for (size_t i = 0; i < 10; i++)
	{
		printf("%x\n", m[i]);
	}
	

	munmap(m, sysconf(_SC_PAGESIZE));

	close_driver(DRIVER_NAME, fd);

	return EXIT_SUCCESS;
}
