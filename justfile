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
tpm_path       := "/tmp/tpm-dev-" + env_var('USER')
default_dbg    := "/tmp/dbg-" + env_var('USER')
default_smp    := "1"
extra_arg      := ""

# Start a GDB session
gdb DBG=default_dbg:
	rust-gdb -q -ex "file target/x86_64-unknown-kernel/debug/first-stage" -ex "target remote {{DBG}}" -ex "source scripts/tyche-gdb.gdb" 

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
rawc SMP=default_smp:
	@just build
	@just tpm
	-cargo run {{cargo_args}} {{x86_64}} {{first-stage}} {{rawc}} -- --smp={{SMP}}

# Run rawc guest, stop to wait for GDB session
rawc-dbg SMP=default_smp:
	@just build
	@just tpm
	-cargo run {{cargo_args}} {{x86_64}} {{first-stage}} {{rawc}} -- --smp={{SMP}} --dbg_path={{default_dbg}} --stop

common TARGET SMP ARG=extra_arg:
	@just build
	@just tpm
	-cargo run {{cargo_args}} {{x86_64}} {{first-stage}} {{TARGET}} -- --uefi --dbg_path={{default_dbg}} --smp={{SMP}} {{ARG}}

# Run the VMM without any guest
no-guest SMP=default_smp:
	@just common {{no-guest}} {{SMP}}

no-guest-dbg SMP=default_smp:
	@just common {{no-guest}} {{SMP}} --stop

# Run rawc guest with UEFI
rawc-uefi SMP=default_smp:
	@just common {{rawc}} {{SMP}}

# Run rawc guest, stop to wait for GDB session.
rawc-uefi-dbg SMP=default_smp:
	@just common {{rawc}} {{SMP}} --stop

# Build linux image.
build-linux:
	make -C linux-image/

# Build the ramfs, packing all the userspace binaries
build-ramfs:
	cargo build --package libtyche --target=x86_64-unknown-linux-musl --release
	cp target/x86_64-unknown-linux-musl/release/tyche linux-image/builds/initramfs/x86-busybox/bin/

	@just build-linux

# Run linux guest with UEFI
linux SMP=default_smp:
	@just common {{linux}} {{SMP}}

# Run linux guest, stop to wait for GDB session.
linux-dbg SMP=default_smp:
	@just common {{linux}} {{SMP}} --stop

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
	if pgrep -u "$(whoami)" swtpm;
	then
		echo "TPM is running"
	else
		echo "Starting TPM"
		mkdir -p {{tpm_path}}/
		swtpm socket --tpm2 --tpmstate dir={{tpm_path}} --ctrl type=unixio,path={{tpm_path}}/sock &
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
