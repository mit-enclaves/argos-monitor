# Justfile, see documentation here:
# https://github.com/casey/just

toolchain      := "nightly-2022-08-01"
target         := "--target x86_64-kernel.json"
build_std      := "-Zbuild-std=core,alloc"
build_features := "-Zbuild-std-features=compiler-builtins-mem"
cargo_args     := target + " " + build_std + " " + build_features
linker-script  := "RUSTFLAGS='-C link-arg=-Tsecond-stage-linker-script.x'"
first-stage    := "--package first-stage --features=first-stage/second-stage"
second-stage   := "--package second-stage"
rawc           := "--features=first-stage/guest_rawc"
linux          := "--features=first-stage/guest_linux"
no-guest       := "--features=first-stage/no_guest"
vga            := "--features=first-stage/vga"
default_dbg    := "gdb0"

# Print list of commands
help:
	@just --list --unsorted

# Build the VMM
build:
	{{linker-script}} cargo build {{cargo_args}} {{second-stage}} --release
	cargo build {{cargo_args}} {{first-stage}}

# Typecheck
check:
	cargo check {{cargo_args}} {{first-stage}}
	cargo check {{cargo_args}} {{second-stage}}

# Run rawc guest
rawc:
	@just build
	-cargo run {{cargo_args}} {{first-stage}} {{rawc}} --

common TARGET DBG:
  @just build
  -cargo run {{cargo_args}} {{first-stage}} {{TARGET}} -- --uefi "--dbg_path={{DBG}}"

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

# Run linux guest with UEFI
linux:
  @just common {{linux}} {{default_dbg}}

# Run linux guest, specify debug socket name.
linux-dbg SOCKET:
  @just common {{linux}} {{SOCKET}}

# Build the VMM for bare metal platform
build-metal:
	@just build
	-cargo run {{cargo_args}} {{first-stage}} {{linux}} {{vga}} -- --uefi --no-run

# Install the required dependencies
setup:
	# Installing Rust
	rustup toolchain install {{toolchain}}
	rustup component add llvm-tools-preview --toolchain {{toolchain}}
	rustup component add rust-src --toolchain {{toolchain}}

	# Download UEFI firmware for QEMU usage
	wget https://github.com/rust-osdev/ovmf-prebuilt/releases/download/v0.20220719.209%2Bgf0064ac3af/OVMF-pure-efi.fd

# The following line gives highlighting on vim
# vim: set ft=make :
