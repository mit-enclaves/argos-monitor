all: sdk_tyche_loader.so sdk_tyche_runtime.so

$(info ARCH="$(ARCH)")

ifeq ($(ARCH), x86)
	GCC = gcc
else ifeq ($(ARCH), riscv)
	GCC = riscv64-unknown-linux-gnu-gcc
endif

$(info GCC="$(GCC)")

# Dependencies for the build.
DRIVER_PATH=../../../linux/drivers/tyche/
LIB_PATH=$(DRIVER_PATH)/libraries/
LIB_PT=../pts
DLL_LIB= $(LIB_PATH)/dll
CAPA_LIB=$(LIB_PATH)/capabilities
COMMON_LIB=$(LIB_PATH)/common
ELF_LIB=../elf64
TYCHE_DRIVER=$(DRIVER_PATH)

# Configuration for loader.
CODE_LOADER = $(wildcard loader/*.c)
HDRS_LOADER = $(wildcard loader/*.h) $(wildcard include/*.h)

# Configuration for the elf64 library.
CODE_ELF64 = $(wildcard $(ELF_LIB)/src/*.c)
HDRS_ELF64 = $(wildcard $(ELF_LIB)/include/*.h)

# Configuration for runtime.
ifeq ($(ARCH), x86)
CODE_RUNTIME = $(wildcard runtime/*.c) $(wildcard runtime/asm.S)
HDRS_RUNTIME = $(wildcard include/*.h)
else ifeq ($(ARCH), riscv)
CODE_RUNTIME = $(wildcard runtime/*.c) $(wildcard runtime/riscv_asm.S)
HDRS_RUNTIME = $(wildcard include/*.h)
endif


# Configure the includes.
COMMON_INCLUDES = -Iinclude -I$(CAPA_LIB)/include -I$(COMMON_LIB)/include -I$(DLL_LIB)/include 
LOADER_INCLUDES = -Iinclude -I$(ELF_LIB)/include -I$(TYCHE_DRIVER)/include $(COMMON_INCLUDES)
WITH_PTS_INCLUDES = $(LOADER_INCLUDES) -I$(LIB_PT)/include

# Configs for dynamic library.
ELF_CONFIG= -Wl,-R $(ELF_LIB) -L$(ELF_LIB)

sdk_tyche_loader.so: $(CODE_LOADER) $(HDRS_LOADER) $(CODE_ELF64) $(HDRS_ELF64)
	make -B -C $(ELF_LIB)
	$(GCC) -DTYCHE_USER_SPACE=1 -g $(WITH_PTS_INCLUDES) -shared -o $@ -fPIC $(CODE_LOADER) $(CODE_ELF64)

# This is mostly to make sure the code compiles.
# When used by a domain, include the code directly as shown below.
sdk_tyche_runtime.so: $(CODE_RUNTIME) $(HDRS_RUNTIME)
	$(GCC) -DTYCHE_USER_SPACE=1 -g $(COMMON_INCLUDES) -shared -o $@ -fPIC $(CODE_RUNTIME)

.PHONY: clean

clean:
	rm -rf sdk_tyche_loader.so sdk_tyche_runtime.so
