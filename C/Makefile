$(info ARCH="$(ARCH)")
$(info CROSS_COMPILE="$(CROSS_COMPILE)")
ifeq ($(ARCH), x86)

all:

ubuntu_mount:
	sudo ./scripts/mount_ubuntu.sh mount ../ubuntu.qcow2 /tmp/mount qcow2

ubuntu_umount:
	sudo ./scripts/mount_ubuntu.sh umount ../ubuntu.qcow2 /tmp/mount

PROGRAMGS_PATH ?= /tmp/mount/tyche/programs
TYCHOOLS_LOCAL_BIN_PATH ?= ../target/release

# Make sure you mount the disk first
update_disk:
	sudo chown --recursive $(shell whoami) /tmp/mount/tyche
	make ARCH=x86 -B -C drivers/tyche install_disk
	make ARCH=x86 -B -C libraries/sdktyche/example/app-selector install_disk
	make ARCH=x86 -B -C libraries/sdktyche/example/simple-enclave install_disk
	make ARCH=x86 -B -C libraries/sdktyche/example/simple-sandbox install_disk
	make ARCH=x86 -B -C libraries/tyche-trusted-runtime install_disk
	cp scripts/install_drivers.sh /tmp/mount/tyche
	cp $(TYCHOOLS_LOCAL_BIN_PATH)/tychools $(PROGRAMGS_PATH)/tychools 
	
else ifeq ($(ARCH), riscv)

TYCHOOLS_RISCV_PATH ?= ../target/riscv64gc-unknown-linux-gnu/release

.PHONY: all 

all: ubuntu_mount compile_riscv_and_update_disk ubuntu_umount 

ubuntu_mount: 
	sudo ./scripts/mount_ubuntu_riscv64.sh mount ../ubuntu_riscv_drive.img /tmp/ubuntu_riscv_mount 

ubuntu_umount: 
	sudo ./scripts/mount_ubuntu_riscv64.sh umount ../ubuntu_riscv_drive.img /tmp/ubuntu_riscv_mount

PROGRAMGS_PATH ?= /tmp/ubuntu_riscv_mount/tyche/programs
TYCHOOLS_LOCAL_BIN_PATH ?= ../target/release

compile_riscv_and_update_disk: 
	sudo chown --recursive $(shell whoami) /tmp/ubuntu_riscv_mount/tyche
	make ARCH=riscv -B -C drivers/tyche install_disk 
	make ARCH=riscv -B -C libraries/sdktyche/example/app-selector install_disk
	make ARCH=riscv -B -C libraries/sdktyche/example/simple-enclave install_disk
	cp scripts/riscv64_install_drivers.sh /tmp/ubuntu_riscv_mount/tyche
	cp scripts/run_eapp.sh /tmp/ubuntu_riscv_mount/tyche
	cp $(TYCHOOLS_RISCV_PATH)/tychools $(PROGRAMGS_PATH)/tychools 

# Use this when you see errors like the following during the boot: 
# EXT4-fs error (device vda1): ext4_validate_block_bitmap:390: comm ext4lazyinit: bg 30: bad block bitmap checksum
# The superblock may have been corrupted and due to failing the checksum matching, the file system will get mounted in "ro" mode, which means you cannot write any logs to files, cannot copy the latest program builds to the /root and so on. 
# This is undesirable. Make sure when running the VM you perform a clean poweroff or clean exit for all programs modifying the disk.  

fix_disk_superblock: 
	echo "fixing disk superblock"
	sudo losetup -P /dev/loop0 ../ubuntu-22.04.3-preinstalled-server-riscv64+unmatched.img 
	sudo fsck -f -y /dev/loop0p1 
	sudo losetup -d /dev/loop0 

endif

