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
Attestation is done through the enclave attestation call, in a way that client is sending a nonce to enclave as a challenge, enclave calls Tyche and Tyche responds with a report. Report should consist of signed attestation key, and data signed by public attestation key, but for now it is without signatures.

Schema of how it works, without signature so far

```
[user space]
Client (has physical offset and generates a nonce)          [checks the hash]
| [puts args in shared buffer]                                     ^
-------------------------------------------------------------------|
| [kernel space]            [reads from shared buff]    [puts results in shared buff, returns]
|----(call the enclave)----> enclave -----|                        ^
----------ENCLAVE_ATTESTATION CALL--------|------------------------|
[Tyche]                                   V [creates the report]   |
                                            -----------------------|
```

Expantion could be for client to do the same thing as tychools/attestation but is there need for it? Next step is creating the signature of the message.

## Next steps

One of the approaches ould be to have a separate domain that is used for hashing/attestation. When tyche receives a call, it then 'forwards' the call to the domain. This way TCB won't be increased, and the mappings of memory in Tyche could be removed. If we can generate std static Rust binaries then we can do it probably. That will be the path to explore.

## Problems

Rust no_std crates (LLVM/target bug)
