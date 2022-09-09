# Injecting Interrupts

Sometimes, we want tyche to capture an interrupt or an exception triggered in the guest, print some useful debugging information, and forward the interrupt to the guest.
For example, an invalid opcode exception while running Linux can either be intentional (i.e., Linux uses `ud2` on purpose), or symptomatic of a mismatch between the emulated CPUID and the configuration of our VMCS. 

Intel provides several mechanisms based on APIC to inject virtual events (potentially asynchronously) into a running VM.
However here, for the particular use case we are interested in, we can take a simpler straightforward approach based on VMCS.

## The VMCS exception bitmap

The VMCS has an `exception_bitmap` 32 bit field that selects which exceptions or interrupts trigger a VM exit.
The different exceptions are listed in `vmx/bitmap.rs` as `ExceptionBitmap`.

## What to do with the exception?

Tyche acquires a `VMExitInterrupt` object by calling `vmcs.interrupt_info()`.
This object contains three elements: 

1. `vector` the vector ID for the interrupt or exception.
2. `int_type` the interrupt type.
3. `error_code` an optional error code, i.e., a more precise error within the interrupt type.

All of these information allow tyche to decide whether or not the interrupt should be forwarded to the guest.

If we decide to do so, the `VMExitInterrupt` needs to be turned into an injectable interrupt, i.e., a 32 bit value for the `VmEntryIntInfoField` field within the VMCS structure.
The value has the following structure

```
valid bit: 1 bit | deliver bit: 1 bit |int_type: 8 bits |vector: 8 bits 
```

The valid bit needs to be set to 1 to deliver the interrupt upon the next VM entry.


## Unclear

The intel documentation seems to suggest that the `deliver` bit must be set to 1 as well, but this triggers an invalid VMCS execption.


