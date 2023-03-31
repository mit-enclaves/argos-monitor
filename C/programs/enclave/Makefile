all: enclave a.out 

# All the library dependencies.
ELF64=../../libraries/elf64
LOADER=../../libraries/enclave
DRIVER=../../drivers/enclave
CAPA=../../libraries/capabilities

# All the includes
INCLUDES= -Iinclude/ -I$(ELF64)/include -I$(LOADER)/include -I$(DRIVER)/include -I$(CAPA)/include

# Enclave includes
TRUSTED_INCLUDES=-I$(CAPA)/include
CAPA_LIB=$(CAPA)/libcapabilities.a

# Dynamic libraries
DYN_LIBS= -l:encl_loader.so -lelf64

# Destination for installation.
DISK_PATH = /tmp/mount/tyche/
INSTALL_PATH = /tyche

a.out: src/main.c enclave 
	mkdir -p libs
	make -C $(ELF64)
	make -C $(LOADER)
	cp $(ELF64)/libelf64.so libs/
	cp $(LOADER)/encl_loader.so libs/
	cp $(LOADER)/encl.so libs/
	gcc -g $(INCLUDES) -Wl,-R ./libs/ -L./libs/ -o $@ $< $(DYN_LIBS)

enclave: trusted/main.c trusted/asm.S $(CAPA_LIB)
	gcc -g $(INCLUDES) -nostdlib -static -o $@ $^

install: a.out enclave
	mkdir -p $(INSTALL_PATH)/enclaves
	cp -r libs $(INSTALL_PATH)/enclaves
	cp -t $(INSTALL_PATH)/enclaves $^

install_disk: a.out enclave
	mkdir -p $(DISK_PATH)/enclaves
	cp -r libs $(DISK_PATH)/enclaves
	cp -t $(DISK_PATH)/enclaves $^


.PHONY: clean

clean:
	rm enclave a.out

