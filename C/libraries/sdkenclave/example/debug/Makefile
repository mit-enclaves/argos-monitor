all: poc-main dbg-main

ifeq ($(ARCH), x86)
        GCC = gcc
else ifeq ($(ARCH), riscv)
        GCC = riscv64-unknown-linux-gnu-gcc
endif

# Libraries
LIB_PATH=../../../
DRIVERS_PATH=../../../../drivers/

SDK=$(LIB_PATH)/sdkenclave
DLL_LIB= $(LIB_PATH)/dll
CAPA_LIB=$(LIB_PATH)/capabilities
COMMON_LIB=$(LIB_PATH)/common

ELF64=$(LIB_PATH)/elf64
PTS=$(LIB_PATH)/pts
DRIVER=$(DRIVERS_PATH)/tyche

# Includes
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

# Dynamic libraries
DYNS= -l:enclave_loader.so -lelf64 -lpts

# Code
SRC_POC=$(wildcard poc/*.S) $(wildcard poc/*.c)

SRC_DBG= $(wildcard src/*.S) $(wildcard src/*.c)

# Installing
ifeq ($(ARCH), x86)
DISK_PATH = /tmp/mount/tyche/debug
else ifeq ($(ARCH), riscv)
DISK_PATH = /home/neelu/vmxvmm/builds/ramfs-riscv/tyche/debug/
endif

poc-main: $(SRC_POC)
	echo $(SRC_POC)
	$(GCC) -g -o $@ $(SRC_POC)

dbg-main: $(SRC_DBG)
	mkdir -p libs
	make -C $(SDK)
	make -C $(ELF64)
	make -C $(PTS)
	cp $(ELF64)/libelf64.so libs/
	cp $(SDK)/enclave_loader.so libs/
	cp $(PTS)/libpts.a libs/
	$(GCC) -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -Wl,-R ./libs  -L./libs/ -o $@ $(SRC_DBG) $(DYNS)

install_disk: dbg-main 
	mkdir -p $(DISK_PATH)
	cp -r libs $(DISK_PATH)
	cp -t $(DISK_PATH) dbg-main

.PHONY: clean

clean:
	rm poc-main dbg-main

