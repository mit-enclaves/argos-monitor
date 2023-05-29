# SPDX-License-Identifier: GPL-2.0

KDIR ?= ../../builds/linux-x86

all: default app

default:
	$(MAKE) -C $(KDIR) M=$$PWD CC=clang

app: app/memory_allocation_app

clean:
	@rm -f *.mod *.c *.ko *.o *.order *.symvers *.d .*.cmd app/memory_allocation_app
