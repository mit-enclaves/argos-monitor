# Tyche

## Setup

This project is controled through a _justfile_, this section details how to
setup the tools needed to build and run the monitors.

### Requirements

This project assumes an Intel x86_64 processor with VT-x capabilities in order
to build and run the x86_64 version. The risc-v version can be built from any
platform.

### Justfiles

This project uses _justfiles_ as a command line runner (think makefiles but
without the build-system bits). To get started [install
just](https://github.com/casey/just#packages), you can also build it from source
if you have rust installed with `cargo install just`.

To list available commands, run `just help`. For instance, the monitor can be
built with `just build`.

To get started with this project, run `just setup`.

### Linux Images

A standard, unmodified Linux image is provided to run on top of the monitor, as
well as a minimal busybox-based distribution. Both Linux and Busybox
configuratons can be found in the `configs/` folder.

In order to build the Linux kernel, follow those steps:

#### For x86_64

These steps assumes you are compiling from an x86_64 machine.

```sh
just init-ramfs-x86
just build-busybox-x86
just build-linux-x86
```

Then you can run the monitor with `just linux`

#### For risc-v

```sh
just init-ramfs-riscv
just build-busybox-riscv
just build-linux-riscv
```

## Usage

The VMM can easily be built and typechecked with:

```sh
# Build the monitor
just build

# Typecheck the monitor
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

## Problems when compiling

If you run into the 'No space left on the device' issue, that means you need to patch the .cargo/registry/.../bootloader/src/bin/builder.rs:255 to add a *1024.
