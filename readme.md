# VMXVMM

A Virtual Machine Monitor based on Intel VT-x.

## Setup

This project uses _justfiles_ as a command line runner (think makefiles but
without the build-system bits). To get started [install
just](https://github.com/casey/just#packages), you can also build it from source
if you have rust installed with `cargo install just`.

To list available commands, run `just help`. For instance, the vmm can be built
with `just build`.

## Usage

The VMM can easily be built and typechecked with:

```sh
# Build the vmm
just build

# Typecheck the vmm 
just check
```

When running the VMM, multiple guests are available. By default, the selected
guest is `RawC`, a small C program that can be used for simple testing. To run
other guests, use:

```sh
# For RawC
just rawc

# For RawC with UEFI
just rawc-uefi

# For Linux
just linux
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

## Booting Ubuntu

Ubuntu images are supported, to use one simple create a `.qcow2` image (follow a
tutorial for that), and add it at the root of this folder with the name
`ubuntu.qcow2`.
