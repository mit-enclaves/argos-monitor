all: app_selector

ifeq ($(ARCH), x86)
        GCC = gcc
else ifeq ($(ARCH), riscv)
        GCC = riscv64-unknown-linux-gnu-gcc
endif

## ————————————————————————————————— Paths —————————————————————————————————— ##
LIB_PATH=../../../
DRIVERS_PATH=../../../../drivers/

## ——————————————————————————————— Libraries ———————————————————————————————— ##
SDK=$(LIB_PATH)/sdktyche
DLL_LIB= $(LIB_PATH)/dll
CAPA_LIB=$(LIB_PATH)/capabilities
COMMON_LIB=$(LIB_PATH)/common
ELF64=$(LIB_PATH)/elf64
PTS=$(LIB_PATH)/pts
DRIVER=$(DRIVERS_PATH)/tyche

## ——————————————————————— Untrusted code and headers ——————————————————————— ##
CODE_UNTRUSTED=$(wildcard untrusted/*.c)
HDRS_UNTRUSTED=$(wildcard include/*.h)

## ———————————————————————— Trusted code and headers ———————————————————————— ##
CODE_TRUSTED=$(wildcard trusted/*.c)
HDRS_TRUSTED=$(wildcard include/*.h)

# Configuration for runtime.
ifeq ($(ARCH), x86)
CODE_RUNTIME = $(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/asm.S)
HDRS_RUNTIME = $(wildcard $(SDK)/include/*.h) 
else ifeq ($(ARCH), riscv)
CODE_RUNTIME = $(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/riscv_asm.S)
HDRS_RUNTIME = $(wildcard $(SDK)/include/*.h)
endif

## ———————————————————————— Loader code and headers ————————————————————————— ##
CODE_LOADER=$(wildcard $(SDK)/loader/*.c) $(wildcard $(SDK)/loader/*.S)
HDRS_LOADER=$(wildcard $(SDK)/include/*.h)

## ————————————————————————— ELF64 code and headers ————————————————————————— ##
CODE_ELF64=$(wildcard $(ELF64)/src/*.c)
HDRS_ELF64=$(wildcard $(ELF64)/include/*.h)

## —————————————————————— Page table code and headers ——————————————————————— ##
CODE_PTS=$(wildcard $(PTS)/src/*.c)
HDRS_PTS=$(wildcard $(PTS)/include/*.h)

## —————————————————————— Application code and headers —————————————————————— ##
CODE_APP=$(CODE_ELF64) $(CODE_PTS) $(CODE_LOADER) $(CODE_UNTRUSTED)
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER) $(HDRS_UNTRUSTED)

## ———————————————————————— Enclave code and headers ———————————————————————— ##
CODE_ENCLAVE=$(CODE_RUNTIME) $(CODE_TRUSTED)
HDRS_ENCLAVE=$(HDRS_RUNTIME) $(HDRS_TRUSTED)

## ———————————————————————————————— Includes ———————————————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

## ————————————————————— Configuration for the install —————————————————————— ##
ifeq ($(ARCH), x86)
DISK_PATH ?= /tmp/mount/tyche/programs 
TYCHOOLS_PATH ?= ../../../../../crates/tychools/ 
else ifeq ($(ARCH), riscv)
#DISK_PATH ?= /home/neelu/vmxvmm/builds/ramfs-riscv/tyche/programs/
DISK_PATH ?= /tmp/ubuntu_riscv_mount/tyche/programs
endif
## ———————————————————————————————— Targets ————————————————————————————————— ##

app: $(CODE_APP) $(HDRS_APP) 
	$(GCC) -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -static -o $@ $(CODE_APP)

enclave: $(CODE_ENCLAVE) $(HDRS_ENCLAVE)
	$(GCC) -DTYCHE_USER_SPACE=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_ENCLAVE)

ifeq ($(ARCH), x86)

app_selector: app enclave
	cargo -C $(TYCHOOLS_PATH) install --path .
	tychools instrument -s manifests/default.json 
	chmod +x app_selector
	rm app enclave

install_disk: all 
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) app_selector 

else ifeq ($(ARCH), riscv)

app_selector: 
	# Blank 

install_disk: all 
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) app enclave
endif

.PHONY: clean

clean:
	rm app_selector
