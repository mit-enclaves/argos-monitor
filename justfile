# Justfile, see documentation here:
# https://github.com/casey/just

toolchain      := "nightly-2022-11-01"
x86_64         := "--target targets/x86_64-unknown-kernel.json"
riscv          := "--target targets/riscv-unknown-kernel.json"
build_std      := "-Zbuild-std=core,alloc"
build_features := "-Zbuild-std-features=compiler-builtins-mem"
cargo_args     := build_std + " " + build_features
linker-script  := "RUSTFLAGS='-C link-arg=-Tsecond-stage-linker-script.x'"
first-stage    := "--package first-stage --features=first-stage/second-stage"
second-stage   := "--package second-stage"
fake-acm       := "--package fake-acm"
rawc           := "--features=first-stage/guest_rawc"
linux          := "--features=first-stage/guest_linux"
no-guest       := "--features=first-stage/no_guest"
vga-s1         := "--features=first-stage/vga"
vga-s2         := "--features=second-stage/vga"
default_dbg    := "gdb0"

# Print list of commands
help:
	@just --list --unsorted

# Build the VMM
build:
	{{linker-script}} cargo build {{cargo_args}} {{x86_64}} {{second-stage}} --release
	cargo build {{cargo_args}} {{x86_64}} {{first-stage}}

build-riscv:
	cargo build {{cargo_args}} {{riscv}} {{second-stage}} --release

# Typecheck
check:
	@# Create an empty file if no second-stage has been compiled yet
	@mkdir -p target/x86_64-unknown-kernel/release
	@touch target/x86_64-unknown-kernel/release/second-stage

	cargo check {{cargo_args}} {{x86_64}} {{first-stage}}
	cargo check {{cargo_args}} {{x86_64}} {{second-stage}}
	cargo check {{cargo_args}} {{x86_64}} {{fake-acm}}
	cargo check {{cargo_args}} {{riscv}}  {{second-stage}}

# Run rawc guest
rawc:
	@just build
	-cargo run {{cargo_args}} {{x86_64}} {{first-stage}} {{rawc}} --

common TARGET DBG:
	@just build
	@just tpm
	-cargo run {{cargo_args}} {{x86_64}} {{first-stage}} {{TARGET}} -- --uefi "--dbg_path={{DBG}}"

# Run the VMM without any guest
no-guest:
	@just common {{no-guest}} {{default_dbg}}

# Run rawc guest with UEFI
rawc-uefi:
	@just common {{rawc}} {{default_dbg}}

# Run rawc guest, specify debug socket name.
rawc-uefi-dbg SOCKET:
	@just common {{rawc}} {{SOCKET}}

# Build linux image.
build-linux:
	make -C linux-image/

# Build the ramfs, packing all the userspace binaries
build-ramfs:
	cargo build --package libtyche --target=x86_64-unknown-linux-musl --release
	cp target/x86_64-unknown-linux-musl/release/tyche linux-image/builds/initramfs/x86-busybox/bin/

	@just build-linux

# Run linux guest with UEFI
linux:
	@just common {{linux}} {{default_dbg}}

# Run linux guest, specify debug socket name.
linux-dbg SOCKET:
	@just common {{linux}} {{SOCKET}}

# Build the VMM for bare metal platform
build-metal-no-guest:
	{{linker-script}} cargo build {{cargo_args}} {{x86_64}} {{second-stage}} {{vga-s2}} --release
	-cargo run {{cargo_args}} {{x86_64}} {{first-stage}} {{no-guest}} {{vga-s1}} -- --uefi --no-run

# Build the VMM for bare metal platform
build-metal-linux:
	{{linker-script}} cargo build {{cargo_args}} {{x86_64}} {{second-stage}} {{vga-s2}} --release
	-cargo run {{cargo_args}} {{x86_64}} {{first-stage}} {{linux}} {{vga-s1}} -- --uefi --no-run

# Start the software TPM emulator, if not already running
tpm:
	#!/usr/bin/env sh
	if pgrep swtpm;
	then
		echo "TPM is running"
	else
		echo "Starting TPM"
		mkdir -p /tmp/tpm-dev/
		swtpm socket --tpm2 --tpmstate dir=/tmp/tpm-dev --ctrl type=unixio,path=/tmp/tpm-dev/sock &
	fi

# Install the required dependencies
setup:
	# Installing Rust
	rustup toolchain install {{toolchain}}
	rustup component add llvm-tools-preview --toolchain {{toolchain}}
	rustup component add rust-src --toolchain {{toolchain}}
	rustup target add x86_64-unknown-linux-musl

	# Download UEFI firmware for QEMU usage
	wget https://github.com/rust-osdev/ovmf-prebuilt/releases/download/v0.20220719.209%2Bgf0064ac3af/OVMF-pure-efi.fd

	# -----------------------------------------------------------
	# IMPORTANT: You might need to perform some additional steps:
	# - Install `swtpm` (software TPM emulator)

# The following line gives highlighting on vim
# vim: set ft=make :
