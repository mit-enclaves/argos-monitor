all: libpts.a test_x86

libpts.a: src/lib.c src/x86_64_pt.c include/pts_api.h include/x86_64_pt.h
	gcc -g -nostdlib -c -Iinclude/ -o pts.o src/lib.c
	gcc -g -nostdlib -c -Iinclude/ -o x86.o src/x86_64_pt.c
	ar rcs $@ pts.o x86.o
	rm pts.o x86.o

test_x86: tests/test.c libpts.a
	gcc -DDEBUG_USER_SPACE=1 -g -Iinclude/ -L. -o $@ $< -l:libpts.a 

.PHONY: clean
clean:
	rm test_x86 libpts.a
