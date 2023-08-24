$(info ARCH="$(ARCH)")

ifeq ($(ARCH), x86)

all:

ubuntu_mount:
	sudo ./scripts/mount_ubuntu.sh mount ../ubuntu.qcow2 /tmp/mount qcow2

ubuntu_umount:
	sudo ./scripts/mount_ubuntu.sh umount ../ubuntu.qcow2 /tmp/mount

# Make sure you mount the disk first
update_disk:
	sudo chown --recursive $(shell whoami) /tmp/mount/tyche
	make ARCH=x86 -B -C drivers/tyche install_disk
	make ARCH=x86 -B -C libraries/sdkenclave/example/enclave install_disk
	make ARCH=x86 -B -C libraries/sdkenclave/example/debug install_disk
	make ARCH=x86 -B -C libraries/trt install_disk
	cp scripts/x86_64_install_drivers.sh /tmp/mount/tyche

else ifeq ($(ARCH), riscv)

.PHONY: all 

all: ubuntu_mount compile_and_exit_riscv ubuntu_umount 

ubuntu_mount: 

	sudo ./scripts/mount_ubuntu_riscv64.sh mount ../ubuntu-22.04.3-preinstalled-server-riscv64+unmatched.img /tmp/ubuntu_riscv_mount 

ubuntu_umount: 
	sudo ./scripts/mount_ubuntu_riscv64.sh umount ../ubuntu-22.04.3-preinstalled-server-riscv64+unmatched.img /tmp/ubuntu_riscv_mount

compile_riscv_and_update_disk: 
	sudo chown --recursive $(shell whoami) /tmp/ubuntu_riscv_mount/tyche
	make ARCH=riscv -B -C drivers/tyche install_disk 
	make ARCH=riscv -B -C libraries/sdkenclave/example/enclave install_disk
	#make ARCH=riscv -B -B libraries/sdkenclave/example/debug install_disk
	#make ARCH=riscv -B -C libraries/trt
	#cp scripts/install_drivers.sh /home/neelu/vmxvmm/builds/ramfs-riscv/
	#cp scripts/run_eapp.sh /home/neelu/vmxvmm/builds/ramfs-riscv/
	#cp libraries/sdkenclave/*.so /home/neelu/vmxvmm/builds/ramfs-riscv/
	cp scripts/riscv64_install_drivers.sh /tmp/ubuntu_riscv_mount/tyche
	cp scripts/run_eapp.sh /tmp/ubuntu_riscv_mount/tyche 
	cp libraries/sdkenclave/*.so /tmp/ubuntu_riscv_mount/tyche/programs

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


