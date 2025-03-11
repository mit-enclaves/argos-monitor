# SEAL benchmark 

This benchmark compiles 2 programs: `seal_stdin_enclave` and `seal_tcp_enclave`.

Both benchmarks copies a modified seal program from `SEAL_SERVER_PATH` which we expect to point to our argos-experiment-seal seal-server version, as `enclave`.
This is then instrumented with tychools to provide seal's mmap buffer as two contiguous segments of 800 pages each and mapped at address `0x700000`.
This is in order to avoid the limitation of linux on contiguous mmaps while providing many pages for seal.

The stdin version takes commands from stdin. It automatically adds the seal terminator `\r\n`.
The tcp version runs a server, by default on port 1234 (but takes an alternative port as arg1).
The tcp server does not modify the input.
