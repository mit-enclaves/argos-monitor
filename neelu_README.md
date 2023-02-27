# Tyche Framework


## Installation and setup cheatsheet for x86\_64: 

1. After cloning the repository, you need to run the following command (if not included with clone): 

`git submodule update --init --recursive`

2. For running the hypervisor, you may need to provide access to the kvm module. 

Note: qemu-system-x86\_64 version used: 6.2.

`sudo chmod 666 /dev/kvm`

3. While building linux (with *just build-linux*), if you come across an issue due to missing gelf.h file, use the following command. 

`sudo apt install libelf-dev`

4. While executing *just linux*, if you come across */bin/sh: can't access tty; job control turned off*, 


## Compiling for RISC-V 

Following this blogpost: https://danielmangum.com/posts/risc-v-bytes-rust-cross-compilation/ 

If you want to skip reading the blogpost, execute the following command: 
`rustup target add riscv64gc-unknown-linux-gnu` 



