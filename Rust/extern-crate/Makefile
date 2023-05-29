# SPDX-License-Identifier: GPL-2.0


CLANG ?= clang
ifeq ($(origin CC),default)
CC := ${CLANG}
endif

# make KDIR=/home/noe/linux
KDIR ?= ../../builds/linux-x86

build-ko:
	cd ext_crate && cargo build -v
	cp ext_crate/target/target/debug/deps/ext_crate-*.o ext_crate.o_shipped
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	@rm -rf \
		.*.cmd *.o *_shipped *.mod *.mod.c *.ko Module.symvers modules.order ext_crate/target
