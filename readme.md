This repository is based on the [`tyche-devel`](https://github.com/epfl-dcsl/tyche-devel) repository.

# Argos Quick Build

Below are instructions for building Argos along with its example FHE applications.

This project assumes an Intel x86_64 processor with VT-x capabilities in order
to build and run the x86_64 version.

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

## Install pre-requisites

These instructions have been tested on Ubuntu 22.04.

Do not use the Ubuntu/debian distribution of `rustup` (from apt-get and/or snap) as this can cause a compilation problem with `rust-src`.

```sh
# Install various prerequisites
$ sudo apt install -y build-essential qemu-system-misc qemu-system-x86 swtpm autoconf bear bison clang cmake flex gcc-multilib libelf-dev libssl-dev libtool ninja-build

# Install rust and cargo
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add cargo to your path, or re-login to your shell
$ . "$HOME/.cargo/env"

# Install just
$ cargo install just
```

## Creating a VM disk image

To start, create an Ubuntu `.qcow2` image for your VM.

```sh
# Download Ubuntu Server 22.04
$ wget https://releases.ubuntu.com/jammy/ubuntu-22.04.5-live-server-amd64.iso

# Create your qcow2 file, here with max size of 50GB
$ qemu-img create -f qcow2 ubuntu.qcow2 50G

# Install Ubuntu to your disk
# NOTE: Be sure to *not* format the disk as an LVM volume during installation, or else the init script for the Argos image will not automount your disk
# NOTE: Be sure to install OpenSSH server during installation for your future convenience.
$ qemu-system-x86_64 \
  -cpu host \
  -machine type=q35,accel=kvm \
  -m 2048 \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -cdrom ubuntu-22.04.5-live-server-amd64.iso \
  -drive file=ubuntu.qcow2,format=qcow2,media=disk

# Recommended: enable autologin for your user on the serial console, once you've booted from your installed disk
$ sudo mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d && echo -e "[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin $USER --noclear --noissue %I 115200 linux" | sudo tee /etc/systemd/system/serial-getty@ttyS0.service.d/override.conf > /dev/null && sudo sync
```

If you get an error `failed to initialize kvm: Permission denied`, you may need to add yourself to the `kvm` group: `$ sudo usermod -a -G kvm yourUserName`

If you are remotely connected to a headless system, make sure to ssh in with X11 forwarding, i.e. use `$ ssh -X yourUserName@yourHost`

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

Additionally, you should have recursively cloned all submodules.

```sh
$ git submodule update --init --recursive
```

Now, we can build the monitor.

```sh
# Build Argos monitor
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

to start Argos. Then, you can easily copy these files from your host to your VM
with `scp`. For example, to copy the sealPIR application:

```sh
$ scp yourHostUsername@10.0.2.2:<path-to-argos-monitor>/C/libraries/sdktyche/sealPIR/seal_stdin_enclave .
```

After copying your compiled enclave applications to your VM, you can run them as:

```sh
$ sudo ~/seal_stdin_enclave
```

## Building for hardware

**Note on selecting hardware**: Argos will print its boot messages and debug information to COM1. It is very helpful and recommended
to use a machine that has a port to COM1 (eg some RS-232 serial port) available, either on the rear I/O panel
or sometimes through a header on the motherboard. Without this, it is difficult to debug any potential issues
with bringing the machine up.

For testing and developing Argos, we used a Dell Optiplex 7050 with an Intel i7-7700 CPU. These are relatively cheap machines
and typically have serial ports on the rear I/O panel.

To build Argos for real, bare-metal hardware:

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

If you have issues with Argos detecting your drive, boot from your normal disk and find the device path of your boot disk,
for example `/dev/sdb3` or `/dev/nvme0n1p2`.

You likely need to edit the `init` script Argos uses for mounting the disk, located at `builds/ramfs-x86/init`.

You then need to rebuild both the ramfs image and the bare-metal Argos image.

```sh
$ just build-ramfs-x86
$ just build-metal-linux
```
