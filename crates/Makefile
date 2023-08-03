DISK_PATH ?= /tmp/mount/tyche/programs/crates
TYCHOOLS_PATH ?= $(DISK_PATH)/tychools
FORK_PATH ?= $(DISK_PATH)/forked_signature
MMU_PATH ?= $(DISK_PATH)/mmu
UTILS_PATH ?= $(DISK_PATH)/utils
VMX_PATH ?= $(DISK_PATH)/vmx

install_disk: 
	# rm -r TYCHOOLS_PATH
	# rm -r FORK_PATH
	mkdir -p $(DISK_PATH)
	mkdir -p $(TYCHOOLS_PATH)
	mkdir -p $(FORK_PATH)
	mkdir -p $(MMU_PATH)
	mkdir -p $(UTILS_PATH)
	mkdir -p $(VMX_PATH)
	cp -r -t $(TYCHOOLS_PATH) tychools/*
	cp -r -t $(FORK_PATH) forked_signature/*
	cp -r -t $(MMU_PATH) mmu/*
	cp -r -t $(UTILS_PATH) utils/*
	cp -r -t $(VMX_PATH) vmx/*