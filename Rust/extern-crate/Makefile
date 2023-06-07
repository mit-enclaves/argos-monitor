# SPDX-License-Identifier: GPL-2.0

KDIR ?= ../../builds/linux-x86

build-ko:
	cd ext_crate && cargo build -v
	cp ext_crate/target/target/debug/deps/ext_crate-*.o ext_crate.o_shipped
	make -C $(KDIR) M=$(PWD) CC=clang

clean:
	make -C $(KDIR) M=$(PWD) clean
	@rm -rf ext_crate/target *.o_shipped
