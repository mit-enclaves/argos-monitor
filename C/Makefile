$(info ARCH="$(ARCH)")

ifeq ($(ARCH), x86)

all:

ubuntu_mount:
	sudo ./scripts/mount_ubuntu.sh mount ../ubuntu.qcow2 /tmp/mount

ubuntu_umount:
	sudo ./scripts/mount_ubuntu.sh umount ../ubuntu.qcow2 /tmp/mount

# Make sure you mount the disk first
update_disk:
	sudo chown --recursive $(shell whoami) /tmp/mount/tyche
	make ARCH=x86 -B -C drivers/tyche install_disk
	make ARCH=x86 -B -C libraries/sdkenclave/example/enclave install_disk
	make ARCH=x86 -B -C libraries/sdkenclave/example/debug install_disk
	make ARCH=x86 -B -C libraries/trt install_disk
	cp scripts/install_drivers.sh /tmp/mount/tyche

else ifeq ($(ARCH), riscv)

all: 

compile_riscv: 
	make ARCH=riscv -B -C drivers/tyche install_disk 
	make ARCH=riscv -B -C libraries/sdkenclave/example/enclave install_disk
	#make ARCH=riscv -B -B libraries/sdkenclave/example/debug install_disk
	#make ARCH=riscv -B -C libraries/trt
	cp scripts/install_drivers.sh /home/neelu/vmxvmm/builds/ramfs-riscv/
	cp scripts/run_eapp.sh /home/neelu/vmxvmm/builds/ramfs-riscv/
	cp libraries/sdkenclave/*.so /home/neelu/vmxvmm/builds/ramfs-riscv/
endif


