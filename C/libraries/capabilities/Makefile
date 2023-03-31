all: libcapabilities.a libcapabilities.so

LIB_DLL=../dll
SRC_FILES =	$(wildcard src/*.c) 
OBJ_FILES = $(patsubst %.c, %.o, $(SRC_FILES)) 
HDR_FILES = $(wildcard include/*.h)

libcapabilities.so: $(SRC_FILES) $(HDR_FILES)
	gcc -g -nostdlib -shared -Iinclude/ -I$(LIB_DLL)/include -o $@ -fPIC $(SRC_FILES) 

%.o : %.c
	gcc -g -nostdlib -Iinclude/ -I$(LIB_DLL)/include -c $< -o $@

libcapabilities.a: $(OBJ_FILES) $(HDR_FILES)
	ar rcs $@ $(OBJ_FILES)
	rm $(OBJ_FILES)

.PHONY: clean

clean:
	rm libcapabilities.so libcapabilities.a

