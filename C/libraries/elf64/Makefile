all: libelf64.so test_elf64

libelf64.so: src/lib.c include/common.h include/elf64.h
	gcc -g -shared -Iinclude/ -o $@ -fPIC src/lib.c 

test_elf64: tests/test.c libelf64.so
	gcc -g -Iinclude/ -Wl,-R . -L. tests/test.c -o $@ -lelf64

.PHONY: clean

clean:
	rm libelf64.so test_elf64
