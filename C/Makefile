all:

ubuntu_mount:
	sudo ./scripts/mount_ubuntu.sh mount ../ubuntu.qcow2 /tmp/mount

ubuntu_umount:
	sudo ./scripts/mount_ubuntu.sh umount ../ubuntu.qcow2 /tmp/mount

PROGRAMGS_PATH ?= /tmp/mount/tyche/programs
TYCHOOLS_LOCAL_BIN_PATH ?= ../target/release

# Make sure you mount the disk first
update_disk:
	sudo chown --recursive $(shell whoami) /tmp/mount/tyche
	make -B -C drivers/tyche install_disk
	make -B -C libraries/sdktyche/example/app-selector install_disk
	make -B -C libraries/sdktyche/example/simple-enclave install_disk
	make -B -C libraries/sdktyche/example/simple-sandbox install_disk
	make -B -C libraries/tyche-trusted-runtime install_disk
	cp scripts/install_drivers.sh /tmp/mount/tyche
	cp $(TYCHOOLS_LOCAL_BIN_PATH)/tychools $(PROGRAMGS_PATH)/tychools 
	