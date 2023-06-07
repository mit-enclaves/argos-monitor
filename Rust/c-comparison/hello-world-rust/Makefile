# SPDX-License-Identifier: GPL-2.0

KDIR ?= ../../../builds/linux-x86

all:
	make -C $(KDIR) M=$(PWD) modules CC=clang

clean:
	make -C $(KDIR) M=$(PWD) clean
