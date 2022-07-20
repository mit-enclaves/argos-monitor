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
