all: app sandbox instrument


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

## ————————————————————— Application code and headers ——————————————————————— ##
CODE_APPLICATION=$(wildcard application/*.c)
HDRS_APPLICATION=$(wildcard include/*.h)

## —————————————————————— Sandboxed code and headers ———————————————————————— ##
CODE_SANDBOXED=$(wildcard sandboxed/*.c)
HDRS_SANDBOXED=$(wildcard include/*.h)

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
CODE_APP=$(CODE_ELF64) $(CODE_PTS) $(CODE_LOADER) $(CODE_APPLICATION)
HDRS_APP=$(HDRS_ELF64) $(HDRS_PTS) $(HDRS_LOADER) $(HDRS_APPLICATION)

## ———————————————————————— Sandbox code and headers ———————————————————————— ##
CODE_SANDBOX=$(CODE_RUNTIME) $(CODE_SANDBOXED)
HDRS_SANDBOX=$(HDRS_RUNTIME) $(HDRS_SANDBOXED)

## ———————————————————————————————— Includes ———————————————————————————————— ##
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include -I$(SDK)/include 
APP_INCLUDES = $(COMMON_INCLUDES) -I$(ELF64)/include -I$(PTS)/include -I$(DRIVER)/include

## ————————————————————— Configuration for the install —————————————————————— ##
DISK_PATH ?= /tmp/mount/tyche/programs 

TYCHOOLS_PATH ?= ../../../../../crates/tychools/ 

## ———————————————————————————————— Targets ————————————————————————————————— ##

app: $(CODE_APP) $(HDRS_APP) 
	gcc -DTYCHE_USER_SPACE=1 -g $(APP_INCLUDES) -o $@ $(CODE_APP)

sandbox: $(CODE_SANDBOX) $(HDRS_SANDBOX)
	gcc -DTYCHE_USER_SPACE=1 -DTYCHOOLS=1 -g $(COMMON_INCLUDES) -nostdlib -static -o $@ $(CODE_SANDBOX)

instrument: app sandbox 
	cargo -C $(TYCHOOLS_PATH) install --path . --locked
	tychools instrument -s manifests/default.json 
	chmod +x simple_sandbox
	rm app sandbox

install_disk: all 
	mkdir -p $(DISK_PATH)
	cp -t $(DISK_PATH) simple_sandbox 


.PHONY: clean

clean:
	rm -rf app sandbox simple_sandbox
