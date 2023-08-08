all:

ubuntu_mount:
	sudo ./scripts/mount_ubuntu.sh mount ../ubuntu.qcow2 /tmp/mount

ubuntu_umount:
	sudo ./scripts/mount_ubuntu.sh umount ../ubuntu.qcow2 /tmp/mount

# Make sure you mount the disk first
update_disk:
	sudo chown --recursive $(shell whoami) /tmp/mount/tyche
	make -B -C drivers/tyche install_disk
	make -B -C libraries/sdktyche/example/app-selector install_disk
	make -B -C libraries/sdktyche/example/simple-enclave install_disk
	make -B -C libraries/sdktyche/example/simple-sandbox install_disk
	make -B -C libraries/tyche-trusted-runtime install_disk
	cp scripts/install_drivers.sh /tmp/mount/tyche
	cp scripts/attestation_startup.sh /tmp/mount/tyche
	make copy_tychools

# not so clean, was done in order to remove Makefile from crates/folder
DISK_PATH ?= /tmp/mount/tyche/programs/crates
TYCHOOLS_PATH ?= $(DISK_PATH)/tychools
FORK_PATH ?= $(DISK_PATH)/forked_signature
MMU_PATH ?= $(DISK_PATH)/mmu
UTILS_PATH ?= $(DISK_PATH)/utils
VMX_PATH ?= $(DISK_PATH)/vmx
CRATES_PATH ?= ../crates/

copy_tychools:
	mkdir -p $(DISK_PATH)
	mkdir -p $(TYCHOOLS_PATH)
	mkdir -p $(FORK_PATH)
	mkdir -p $(MMU_PATH)
	mkdir -p $(UTILS_PATH)
	mkdir -p $(VMX_PATH)
	cp -r -t $(TYCHOOLS_PATH) $(CRATES_PATH)/tychools/*
	cp -r -t $(FORK_PATH) $(CRATES_PATH)/forked_signature/*
	cp -r -t $(MMU_PATH) $(CRATES_PATH)/mmu/*
	cp -r -t $(UTILS_PATH) $(CRATES_PATH)/utils/*
	cp -r -t $(VMX_PATH) $(CRATES_PATH)/vmx/*