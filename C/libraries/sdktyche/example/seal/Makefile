all: seal_enclave

ARCH ?=x86
GCC ?=gcc
KVM ?=1

ifeq ($(ARCH), x86)
        GCC = gcc
else ifeq ($(ARCH), riscv)
        GCC = riscv64-unknown-linux-gnu-gcc
		KVM = 0
endif

ifeq ($(KVM), 1)
	LOADER_BACKEND = -DRUN_WITH_KVM=1
endif


## ————————————————————————————————— Paths —————————————————————————————————— ##
LIB_PATH=../../../
LIB_DRIVER=../../../../../linux/drivers/tyche/libraries/
DRIVERS_PATH=../../../../../linux/drivers/
LINKER_SCRIPT=../../../../../configs/riscv-linker-script-domain.x

## ——————————————————————————————— Libraries ———————————————————————————————— ##
SDK=$(LIB_PATH)/sdktyche
DLL_LIB= $(LIB_DRIVER)/dll
CAPA_LIB=$(LIB_DRIVER)/capabilities
COMMON_LIB=$(LIB_DRIVER)/common
ELF64=$(LIB_PATH)/elf64
PTS=$(LIB_PATH)/pts
DRIVER=$(DRIVERS_PATH)/tyche
CONTALLOC=$(DRIVERS_PATH)/contalloc
RB=$(LIB_PATH)/ringbuf

## ——————————————————————— Untrusted code and headers ——————————————————————— ##
CODE_UNTRUSTED=$(wildcard untrusted/*.c)
HDRS_UNTRUSTED=$(wildcard include/*.h)

# ———————————————————————— Code capabilities library ————————————————————————— #
CODE_CAPAS=$(wildcard $(CAPA_LIB)/src/*.c)
## ———————————————————————— Loader code and headers ————————————————————————— ##
CODE_LOADER=$(wildcard $(SDK)/loader/*.c) $(wildcard $(SDK)/loader/*.S)
HDRS_LOADER=$(wildcard $(SDK)/include/*.h)

ifeq ($(KVM), 1)
	CODE_LOADER+=$(SDK)/loader/backends/back_kvm.c
else
	CODE_LOADER+=$(SDK)/loader/backends/back_tyche.c
endif

## ————————————————————————— ELF64 code and headers ————————————————————————— ##
CODE_ELF64=$(wildcard $(ELF64)/src/*.c)
HDRS_ELF64=$(wildcard $(ELF64)/include/*.h)

## —————————————————————— Page table code and headers ——————————————————————— ##
CODE_PTS=$(wildcard $(PTS)/src/*.c)
HDRS_PTS=$(wildcard $(PTS)/include/*.h)

## —————————————————————— Application code and headers —————————————————————— ##
CODE_APP=$(CODE_ELF64) $(CODE_PTS) $(CODE_LOADER) $(CODE_UNTRUSTED)
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER) $(HDRS_UNTRUSTED)

## ———————————————————————————————— Includes ———————————————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include -I$(RB)/include

ifeq ($(KVM), 1)
	APP_INCLUDES+=-I$(CONTALLOC)/include 
endif

## ————————————————————— Configuration for the install —————————————————————— ##
ifeq ($(ARCH), x86)
DISK_PATH ?= /tmp/mount/tyche/programs 
else ifeq ($(ARCH), riscv)
DISK_PATH ?= /tmp/ubuntu_riscv_mount/tyche/programs
endif

TYCHOOLS_PATH ?= ../../../../../crates/tychools/

# TODO: make that clean
#SEAL_SERVER_PATH ?= ../../../../../../tyche-experiment-seal/SEAL/build/bin/sealexamples
SEAL_SERVER_PATH ?= ../../../../../../tyche-experiment-seal/SealPIR/bin/main

## ———————————————————————————————— Targets ————————————————————————————————— ##

stdin_app: $(CODE_APP) $(HDRS_APP)
	$(GCC) -DTYCHE_USER_SPACE=1 $(LOADER_BACKEND) -g $(APP_INCLUDES) -o $@ $(CODE_APP)

tcp_app: $(CODE_APP) $(HDRS_APP)
	$(GCC) -DRUN_TCP=1 -DTYCHE_USER_SPACE=1 $(LOADER_BACKEND) -g $(APP_INCLUDES) -o $@ $(CODE_APP)

enclave:
	test -s $(SEAL_SERVER_PATH) && cp $(SEAL_SERVER_PATH) $@


seal_enclave: stdin_app  enclave #tcp_app
	cargo -Z unstable-options -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/stdin.json
	chmod +x seal_stdin_enclave
	#rm stdin_app enclave

install_disk: all 
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) seal_stdin_enclave seal_tcp_enclave

objdump_app_headers: $(SEAL_SERVER_PATH)
	objdump -x $^ > header_seal.out

objdump_app_dissa: $(SEAL_SERVER_PATH)
	objdump -S $^ > dissa_seal.out

objdump_encl_headers: seal_stdin_enclave
	objdump -x $^ > header_seal_enclave.out

objdump_encl_diss: seal_stdin_enclave
	objdump -S $^ > dissa_seal_enclave.out


.PHONY: clean

clean:
	rm -f seal_stdin_enclave seal_tcp_enclave stdin_app tcp_app enclave
