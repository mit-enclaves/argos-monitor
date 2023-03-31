all: test

test: tests/main.c include/dll.h ../common/include/common.h
	gcc -ggdb -Iinclude/ -I../common/include -o $@ $<

.PHONY: clean

clean:
	rm test
