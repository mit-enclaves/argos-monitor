# 009 - Attestation

## What

This is an overview of how attestation works for now.

## How

During 'seal' monitor call, RegionCapa info is hashed to get the hash (measurement) of the enclave. Measurement includes
-  regions data
-  access rights
-  confidential/shared information
The hash is stored in the domain strucuture after that. It is saved by capa engine call to save hash into the domain. Comparison is done offline as well using crates/tychools/attestation.rs.
Added flag to Tychools binary to be able to tell whether we want certain segment to be hashed.
Added Tyche call for getting back the hash (similar call will be used for attestation), with code 'ENCLAVE_ATTESTATION = 14'. 

Tyche will have pair of keys representing device keys, coming from Root of Trust probably. Private device key is used to sign public attestation key, and public attestaion key is used to sign enclave hash, offset and data.
Attestation is done through the enclave attestation call, in a way that client is sending a nonce to enclave as a challenge, enclave calls Tyche and Tyche responds with a report. Report should consist of signed attestation key, and data signed by public attestation key.

## Implementation

Schema of how it works

```
[user space]
Client (has physical offset and generates a nonce)          [checks the hash]---->TYCHOOLS
| [puts args in shared buffer]                                     ^
-------------------------------------------------------------------|--------------
| [kernel space]            [reads from shared buff]    [puts results in shared buff, returns]
|----(call the enclave)----> enclave -----|                        ^
----------ENCLAVE_ATTESTATION CALL--------|------------------------|--------------
[Tyche]                                   V [creates the report]   |
                                            -----------------------|
```
For now there is only one keypair per attestation because we still don't have possibility to encrypt data, just to sign/verify it. That could be thing to fix in the whole proceess. Report consists of signature of enclave hash and nonce, plus public signature key (plain). Client then calls tychools lib to check whether using offset, nonce and public key can be sure that the data is properly signed. 
Better thing would be to have encryption of keys, rather then signature/verification, then we would have only device key pair which would be transmitted not encrypted. 
ENCLAVE_ATTESTATION comes with a mode in which we want to call it for certain enclave (0 - calculate report and return some data, 1 - read remaining parts of the report). This is becaus of size of the signature and keys, because we cannot transfer everything using only one call now.

## Running

Running the example
- before running VM instead of doing make in simple-enclave folder, you can do ./make_scirpt.sh to get both the binary to run in VM and binary to attest through tychools named enclave_iso
- enclave_iso is binary embedded as section (Adrien explained it in https://github.com/CharlyCst/vmxvmm/blob/main/design/008-sdktyche-overview.md)
- attestation_startup is to enable internet on .qcow2 image as well as install drivers
- apart from given response, output of tychools during verification of signature can be seen as well
```
./attestation_startup.sh
cd programs
./simple_enclave
-------------------------part of the output when tychools verifies signature
2023-08-04T13:28:12.864Z INFO  [tychools::attestation] Verified!
[LOG @untrusted/main.c:80 read_tychools_response] Answer from tychools

[LOG @untrusted/main.c:84 read_tychools_response] Message verified
```

## Next steps

One of the approaches would be to have a separate domain that is used for hashing/attestation. When Tyche receives a call, it then 'forwards' the call to the domain. This way TCB won't be increased, and the mappings of memory in Tyche could be removed. If we can generate std static Rust binaries then we can do it probably. That will be the path to explore.

## Problems

Rust no_std crates (LLVM/target/std bug). Every rust crate had some kind of a problem when I tried to include it. It requested std when I explicitly added only feature flags for no_std. Other error was for Sha2 and crates that depend on it, had a llvm error: do not know how to split the result of this operator error. In the end forked a repo and swapped getrandom crate with just returning always the same array. It should be worked on later on.
