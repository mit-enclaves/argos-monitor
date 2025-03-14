This repository is based on the [`tyche-devel`](https://github.com/epfl-dcsl/tyche-devel) repository.

# Argos Quick Build

Below are instructions for quickly building Argos along with its example FHE applications.

More detailed documentation for the rest of Tyche is farther below in the document.

These instructions assume you are building on an Intel x86_64 processor with VT-x capabilities. You must also have [Rust](https://www.rust-lang.org/tools/install) and [Qemu](https://www.qemu.org/download/#linux) installed.

## Note on modifications

Changes to Tyche that were made for supporting Argos have mostly been prepended with a comment citing `// Argos` or are
functions with `argos` in the name. In particular, we added support for interacting with the TPM, added vmcalls for Argos
applications to create their I/O transcript, and added an additional enclave-measurement system for Argos attestations.

The vmcalls can be found in `monitor/tyche/src/monitor.rs`. Some additional vmcalls have been added there, which were useful
for benchmarking purposes or PoC work.

For an example of using the transcript-related vmcalls, use the `argos_transcript_example` branch of [`argos-experiment-seal`](https://github.com/mit-enclaves/argos-experiment-seal/tree/argos_transcript_example).

The measurement work can be found in `montior/tyche/src/x86_64/platform.rs:measure` and an example of generating the same
measurement outside of monitor, i.e. from the enclave ELF directly, is in the sdktyche loader application
`C/libraries/sdktyche/loader/lib.c`.

We added several additional enclave applications, the loaders are built from and found at:
 - `C/libraries/sdktyche/example/seal`
 - `C/libraries/sdktyche/example/sealPIR`
 - `C/libraries/sdktyche/example/sealAPSI`

## Creating a VM disk image

To start, create an Ubuntu `.qcow2` image for your VM.

```sh
# Download Ubuntu Server 22.04
$ wget https://releases.ubuntu.com/jammy/ubuntu-22.04.5-live-server-amd64.iso

# Create your qcow2 file, here with max size of 50GB
$ qemu-img create -f qcow2 ubuntu.qcow2 50G

# Install Ubuntu to your disk
# NOTE: Be sure to *not* format the disk as an LVM volume during installation, or else the init script for the Tyche image will not automount your disk
$ qemu-system-x86_64 \
  -cpu host \
  -machine type=q35,accel=kvm \
  -m 2048 \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -cdrom ubuntu-22.04.5-live-server-amd64.iso \
  -drive file=ubuntu.qcow2,format=qcow2,media=disk

# Optional: enable autologin for your user on the serial console, once you've booted from your installed disk
$ sudo mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d && echo -e "[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin $USER --noclear --noissue %I 115200 linux" | sudo tee /etc/systemd/system/serial-getty@ttyS0.service.d/override.conf > /dev/null && sudo sync
```

## Building the monitor

If you are here, you should have cloned at least `argos-experiment-seal` and
`wolftpm-sys` in the parent folder to `argos-monitor`, such that the folder hierarchy
looks like this:

```sh
argos
├── argos-monitor
├── argos-experiment-seal
└── wolftpm-sys
```

Now, we can build the monitor.

```sh
# Build Tyche monitor
$ just setup
$ just init-ramfs-x86

# Follow the instructions to create null/tty/console devices in ramfs
$ sudo mknod ./builds/ramfs-x86/dev/null c 1 3
$ sudo mknod ./builds/ramfs-x86/dev/tty c 5 0
$ sudo mknod ./builds/ramfs-x86/dev/console c 5 1

$ just build-busybox-x86
$ just build-linux-x86
```

## Building enclave applications

```sh
$ cd ../argos-experiment-seal
# Recursively cloning submodules for argos-experiment-seal may take a while
$ git submodule update --init --recursive
$ just refresh # Compiles all examples

# Instrument SEAL applications as enclaves
$ cd ../argos-monitor
$ make -C C update_seal
```

Now, the untrusted enclave loader and the enclave have been built to `C/libraries/sdktyche/example/seal/seal_stdin_enclave` and `C/libraries/sdktyche/example/sealPIR/seal_stdin_enclave` and `C/libraries/sdktyche/example/sealAPSI/seal_stdin_enclave`.

These applications need to be copied to the VM to launch.

## Launching the VM

With your `ubuntu.qcow2` image placed in this folder, simply run

```sh
$ just linux
```

to start Tyche. After copying your compiled enclave applications to your VM,
for instance via SSH to your host from the VM, you can run them as:

```sh
$ sudo ~/seal_stdin_enclave
```

## Building for hardware

**Note on selecting hardware**: Tyche will print its boot messages and debug information to COM1. It is very helpful and recommended
to use a machine that has a port to COM1 (eg some RS-232 serial port) available, either on the rear I/O panel
or sometimes through a header on the motherboard. Without this, it is difficult to debug any potential issues
with bringing the machine up.

For testing and developing Argos, we used a Dell Optiplex 7050 with an Intel i7-7700 CPU. These are relatively cheap machines
and typically have serial ports on the rear I/O panel.

To build Tyche for real, bare-metal hardware:

```sh
$ just build-metal-linux
```

This will produce `target/x86_64-unknown-kernel/debug/boot-uefi-s1.img`

`boot-uefi-s1.img` should be copied to a USB drive, then you should boot your machine from that USB drive.

```sh
# Assuming your USB drive is at /dev/sda
$ sudo dd if=boot-uefi-s1.img of=/dev/sda bs=4M && sync
```

Your machine should have its own real physical disk that has already been provisioned with Ubuntu 22.04, similar
to the instructions before on creating an image for your VM. For your ease, remember to avoid using LVM for partioning
your disk.

If you have issues with Tyche detecting your drive, boot from your normal disk and find the device path of your boot disk,
for example `/dev/sdb3` or `/dev/nvme0n1p2`.

You likely need to edit the `init` script Tyche uses for mounting the disk, located at `builds/ramfs-x86/init`.

You then need to rebuild both the ramfs image and the bare-metal Tyche image.

```sh
$ just build-ramfs-x86
$ just build-metal-linux
```

---
# Tyche

## Setup

This project is controled through a _justfile_, this section details how to
setup the tools needed to build and run the monitors.

### Requirements

This project assumes an Intel x86_64 processor with VT-x capabilities in order
to build and run the x86_64 version. The risc-v version can be built from any
platform.

### rustup,  cargo, and just

Do not use the Ubuntu/debian distribution of `rustup` (from apt-get and/or snap) as this can cause a compilation problem with `rust-src`.

Instead, follow the instructions in `https://www.rust-lang.org/tools/install`

Check that `which rustc` and `which cargo` both point to `$HOME/.cargo/bin`

This project uses _justfiles_ as a command line runner (think makefiles but
without the build-system bits). 

To install `just` from sources: `cargo install just`.

To list available commands, run `just help`. 

To get started with this project, run `just setup`.

Later, just is used during development.  For instance, the monitor can be
built with `just build`.

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

We also provide some scripts to quickly setup a new VM in the `scripts/new-vm` folder.
To use them, execute the following commands
```bash
cd ./scripts/new-vm
# Create VM image based on ubuntu cloud image
./tyche-create-new-vm.sh -image-name tyche-base.qcow2
# We need to start the VM once, to apply the cloud-init config. Terminate the VM after you reach the login prompt
./tyche-run-setup.sh -vm-image ./tyche-base.qcow2 -config-blob ./config-blob.img
# Finally, we need to adjust he partition layout, because tyche's init script is currently quite limited and expects things in a certain order. On the Prompt, double check that the selected filesytem is the "main" partition
./tyche-convert-image.sh -in tyche-base.qcow2 -out ../../ubuntu.qcow2
```
The final image is now ready to use and placed in `tyche-devel/ubuntu.qcow` where it gets picked up by the regular `just linux` command.
