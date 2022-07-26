# VMXVMM

A Virtual Machine Monitor based on Intel VT-x.

## Setup

Requires a nightly rust toolchain. For Rust versions installed with `rustup`
this can be done with:

```sh
rustup toolchain install nightly
```

## Usage

Due the current setup the build steps are a bit more complicated than with
standard Rust projects. To ease development the appropriate aliases to standard
commands are defined in `.cargo/config.toml`:

```sh
# Run the kernel in Qemu (text mode)
cargo krun

# Typecheck the kernel
cargo kcheck

# Build the image for deployment on real hardware (VGA mode)
cargo kimage
```

By default, the selected guest is `RawC`, a small C program that can be used for
simple testing. To run other guests, use:

```sh
# For RawC (default)
cargo krun-rawc

# For Linux
cargo krun-linux

# For self-virtualization
cargo krun-identity
```

## UEFI boot

Our current bootloader supports both BIOS and UEFI boots, but UEFI is currently
required for Linux guests (for performance reasons). To boot with UEFI first
download the OVMF UEFI firmware at the root of this repo with:

```sh
 wget https://github.com/rust-osdev/ovmf-prebuilt/releases/download/v0.20220719.209%2Bgf0064ac3af/OVMF-pure-efi.fd
```

And then run:

```sh
cargo krun-linux
```
