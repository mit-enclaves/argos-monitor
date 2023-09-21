all: app_selector


## ————————————————————————————————— Paths —————————————————————————————————— ##
LOCAL_LIB=../../../
DRIVERS_PATH=../../../../../linux/drivers
DRIVER_LIB=$(DRIVERS_PATH)/tyche/libraries

## ——————————————————————————————— Libraries ———————————————————————————————— ##
SDK=$(LOCAL_LIB)/sdktyche
DLL_LIB= $(DRIVER_LIB)/dll
CAPA_LIB=$(DRIVER_LIB)/capabilities
COMMON_LIB=$(DRIVER_LIB)/common
ELF64=$(LOCAL_LIB)/elf64
PTS=$(LOCAL_LIB)/pts
DRIVER=$(DRIVERS_PATH)/tyche

## ——————————————————————— Untrusted code and headers ——————————————————————— ##
CODE_UNTRUSTED=$(wildcard untrusted/*.c)
HDRS_UNTRUSTED=$(wildcard include/*.h)

## ———————————————————————— Trusted code and headers ———————————————————————— ##
CODE_TRUSTED=$(wildcard trusted/*.c)
HDRS_TRUSTED=$(wildcard include/*.h)

## ———————————————————————— Runtime code and headers ———————————————————————— ##
CODE_RUNTIME=$(wildcard $(SDK)/runtime/*.c) $(wildcard $(SDK)/runtime/*.S)
HDRS_RUNTIME= $(wildcard $(SDK)/include/*.h)

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
DISK_PATH ?= /tmp/mount/tyche/programs 

TYCHOOLS_PATH ?= ../../../../../crates/tychools/ 

## ———————————————————————————————— Targets ————————————————————————————————— ##

app: $(CODE_APP) $(HDRS_APP) 
	gcc -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -o $@ $(CODE_APP)

enclave: $(CODE_ENCLAVE) $(HDRS_ENCLAVE)
	gcc -DTYCHE_USER_SPACE=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_ENCLAVE)

app_selector: app enclave
	cargo -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/default.json 
	chmod +x app_selector
	rm app enclave

install_disk: all 
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) app_selector 


.PHONY: clean

clean:
	rm app_selector
