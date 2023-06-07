# SPDX-License-Identifier: GPL-2.0

KDIR ?= ../../builds/linux-x86

APP_TARGET=app/memory_allocation_app

all: build-ko app

build-ko:
	make -C $(KDIR) M=$(PWD) modules CC=clang

app: $(APP_TARGET)

clean:
	make -C $(KDIR) M=$(PWD) clean
	@rm $(APP_TARGET)
