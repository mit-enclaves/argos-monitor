# Description

The `main.c` file defines a small program that mmaps the QEMU file-backed memory, i.e., `/tmp/tyche` and then proceeds to get stuck in an infinite loop in ` gdb_block`. 

The generated binary `debugger` is meant to run in a gdb session triggered by the `scripts/tyche-gdb` command.
This session will break on `gdb_block` and start a python server servicing commands sent from the qemu-attached gdb session.
You should not have to run the `debugger` binary yourself, with or without gdb.
In case of failure, the debugger output is available in `/tmp/debugger.out`.
Furthermore, the initial process and the debugger use `/tmp/guest_info` to exchange two values:
1. guest (0 -> rawc, 1 -> linux)
2. guest offset address (begining of the guest{rawc, linux} ram)
 
Here is a diagram of the execution: 

```
P1: cargo krun-rawc -- -S    ******************************
                                | gdb session attached |
                                |                      |
P2: ./scripts/tyche-gdb rawc ******************************
            *
            **********> gdb ./debugger/debugger -ex "source scripts/debuger.gdb"
                                    |
                                    _______> mmaps /tmp/tyche
                                    _______> output available on /tmp/debugger.out
```
