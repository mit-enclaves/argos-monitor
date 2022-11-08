# Related Work

## Table of Content

* [Xen](#xen)
* [TrustVisor](#trustvisor) 
* [Inktag](#inktag)
* [Virtual Ghost](#virtual-ghost)
* [Keystone](#keystone)
* [AMD SNP](#amd-snp)
* [Requirements for Virtualization](#requirements-for-virtualization)
* [Nexen](#nexen)
* [Disagregated Xen](#improving-xen-security-through-disaggregation)
* [Nested kernel](#nested-kernel) 
* [CloudVisor](#cloudvisor)
* [Secured Guest VM with SVA](#) TODO
* [Hyperkernel](#) TODO
* [Protecting Cloud Virtual Machines...](#) TODO

---

## Xen

*date*: 2003
### abstract
x86 machine monitor with idealized virtual machine abstraction.
Requires to port existing OSes.
Good performance promise.

### introduction
Seems to focus on performance isolation, e.g., scheduling and access to disks/network.

### Xen approach and overview
Paravirtualization.
Makes physical resources directly visible to the guest.
Domain is the VM where the guest executes.

*Memory management*
Guest OS can directly read but not write pages (has to be validated by hyper)
Xen exists in a 64MB space at the top of every address space.

*CPU*
exception handlers registered with Xen.
Execute the OS in ring1
For fault, only need to virtualize CR2 (we do not need that with VT-x)

*Syscalls*
Direct handler without interposition.
They validate a fast handler and register it with the hardware?
How do they do this?

*Interrupts*
lightweight system events.

*Device I/O*
Asynch rings

### Detailed design
hypercalls (synchronous) and events (asynch)
subsystem virtualization (CPU, timers, memory, network, disk)
Time -> necessity of having virtual is to have fair sharing between processes it schedules
Memory -> reference count and tags, retag only when ref count is 0.
Memory reservation for physical pages (and balloon drivers).

----

## TrustVisor

*date*: 2010

### Comments:
1. The most interesting part is the attestation.
2. PALs are isolated, no notion of SGX-like mixed world.
3. Seems to be really limited in terms of code it can support (self contained world).

### abstract
Intel and AMD features to survive a compromised OS.
Special purpose hypervisor with code integrity and data integrity/secrecy for selected portions of applications.
7% overhead.
6K lines of hypervisor code.

### Introduction

Trusted micro TPM.
Apparently give attestation of user code and inputs/outputs called *execution intergrity*.

### Adversary model 
Extensive description of threat model -> :warn: might want it as inspiration.

### Background
Dynamic root of trust for measurement (DRTM) -> measurement that is then available in special registers (PCR).

### Trustvisor design
Pieces of application Logic (PAL) executed on total isolation of OS.
3 modes of execution -> host, legacy, and secure guest.
Does marshalling with deep copy to pass arguments.

----

## Inktag

*date*: 2013

### Comments:
1. Paraverification is just a step that communicates high-level info to hypervisor.
2. :warn: They have an embryon of negociation as they involve the app on page updates.
-> See the paraverification paragraph below

### abstract
Confidential and integrity-protected applications.
paraverification -> force OS to participate in its own verification.
Attribute based access control and decentralized access control policies.
Support for recoverability (e.g., after system crashes).

### Introduction
verify an untrusted commodity OS behavior with assistance from hypervisor.
Seems to target Iago attacks specifically.

### Overview
Protects application code, data, control flow.
Can share data with other apps.
Directly talk with the hypervisor.
Executes in High-assurance process (HAP).
Guarantees include: 
1. Control flow integrity (hyper saves state of HAP on context switch)
2. Address space integrity -> weird, it encrypts decrypts it all the time.
3. File I/O they track files to ensure mmap stays correct.
Maintains hash of pages for crash consistency.

### Address space management
OID -> object file descriptors (how inktag  manages entities).
They have S-pages.
S-pages: basic mechanism for memory privacy, blocks of 4KB in memory or on disk + metadata.
Hash of content, OID it belongs to etc.

Oh-oh: they interpose on accesses to S-pages to encrypt/decrypt on the fly. That sucks.

They have a trusted EPT for the HAP and untrusted one for the rest of the system.

### Paraverification
Interprets  low level updates to higher level intensions? That part is not super clear to me.
Looks like they ask for confirmation from the application.

Okay so on update -> call the hypervisor to correlate the update with a high-level app request.
For that, they use tokens provided by the HAP.

### Access token
Decentralized groups etc. Not super duper interesting.

### Interrupts
disable vectoring (to avoid executing OS in HAP) -> disable bits in VMCS
Saves and clears the context of interrupt.

----

## Virtual Ghost

*date*: 2014

### Comments:
1. Interesting point -> being able to reuse the mechanism for the OS itself.
2. Interesting point2 -> does not require to run OS at lower privilege level.
  * Instead they compile the kernel such that accesses to resources is checked.
3. Limited to 3 distinct spaces in an address space (we could support multiple enclaves per process).
4. Check SVA, it might be interesting.

### abstract
protect applications by usiing ghost memory, i.e., memory that the OS cannot read or write.
All provided by layer between OS and hardware, provides encryption and signature.
Better than InkTag on some benchmarks.

### Introduction
VG enforces CFI in the kernel and prevents code injection.
Obtain ghost memory via a modified libc.
How do you know it's the application running?
Select whether encryption should be used or not for IO.
Have a notion of secured application key.

### Threat model
They describe 5 different vectors (Iago is the firth) and claim to protect against all but a subset of the 5th.

### Secure computation programming model
3 address space partitions: OS, App, Ghost memory (only app and virtual ghost).

2 new syscalls to support alloc/free of ghost memory.

### Enforcing secure computation
Sandbox memory accesses in the OS.
Uses secure virtual architecture (SVA) controls interactions between system software, hardware, and applications.
SVA compiler technique to interpose between system and hardware (virtual machine abstraction).
Oh looks like heavy duty checks on loads and store operations.
signal handler -> copying context from and to the thread private stack. 

----

## Keystone

### Comments:
1. They expect the enclave to have its own runtime acting as supervisor mode.
That is the first issue with the design -> single programming model.
2. They all identify the problem but never address it -> NOT BEING LOCKED INTO A HARDWARE PLATFORM MEANS YOU HAVE A SOLUTION THAT DOES NOT DEPEND ON HARDWARE AND USES TECHNOLOGIES AS ACCELERATORS
3. Important point is to be able to move trust around, i.e., decide to privatise or not a page dynamically.
4. A point that everybody is missing is WHY WOULD THE HYPERVISOR TRUST THESE TECHNOLOGIES.
Related point -> find out if revocation is possible in keystone.
5. Again despite what they say, it sounds like a trusted environment has only the notion of u vs s separation, no sandboxing within the domain.
6. Requires contiguous physical memory regions
7. They all forget that trust goes both ways, the OS should keep its prerogatives.
8. They have the notion of limiting SM to checking and enforcing configuration, no management.
reference monitor -> *check the related work*

### abstract 
A programmable layer beneath the OS.

### Introduction

They have a point about the fact that you lock yourself into the hardware technology you pick.
They argue about the fact that these are single design points.
Limitation of Komodo is that some of the design decisions/features are baked into the implementation, eg. the boundary between trusted and untrusted.
*Physical Memory Protection* (PMP) arbitrary protection of physical resources.
They expect the enclave to have its own runtime.
*Eyrie* the runtime (RT), libc, syscalls, and some primtives.

### Customizable TEEs

Devs have to compromise to fit their requirements based on what the platform offers.
This often results in an explosion of the TCB.

Keystone goal is to be able to move the boundary in software, performed by isolated regions.

They have a plugin mechanism to allow to adapt to requirements and address new vulnerabilities.
Basically, you can turn on/off features (e.g., memory encryption I guess).

Requirements for the Keystone hardware:
1. A private key for the root of trust
2. hardware source of randomness
3. trusted boot process

### Keystone Overview

Risc-V has 3 modes:
1. U-mode (user)
2. S-mode (supervisor)
3. M-mode (machine) -> direct access to physical resources (interrupts, memory, devices)

What they add: a security monitor (SM) using the fact that M-mode is programmable, control delegation of interrupts and exceptions, and physical memory protection (PMP).
They have a risc-V ABI and the RT talks to the SM -> *once again where is the prerogative of the OS?*.

Each layer has an abstraction of the one below and can check the security guarantees of the ones above it.

TCB is configurable based on what you include in the Eapp -> *that argument is a bit dubious*

They have an interface to perform calls into the untrusted OS.

### Keystone internals
PMP is similar to the IBM 360
It has arbitrary size between 4bytes and DRAM size!!! THAT IS COOL.
Memory allocation has to be contiguous apparently.
Oh but the SM has to dynamically switch permission bits upon switches. 
So it does not have a notion of UID or entity ID.
*Not sure I got everything but it sounds like there is a lot of bookeeping in the SM for transitions*

The SM walks the page table provided by the OS after loading the enclave.

The OS cannot modify or observe the mappings, mem management is done by the enclave after it is started.
*Is that the right design? The OS does not have control over the resources after that? Check what they say about resizing*

### Keystone framework

Ah resizing involves the host OS.
Plugins for various cases (e.g., page eviction, cache partitionning -> that's great).

They have an untrusted buffer for ecalls and a vtable (table of indexed functions exposed by the untrusted part of the program). They require deep-copy as well.
This can be used to expose syscalls.

No parallel multi core enclave execution.

----

## AMD SNP

### comments:
1. A page can belong to only one guest? What about sharing between VMs?
2. The page transition diagram is interesting and what Ed was asking about.
Maybe mix that up with the ability to address regions rather than individual pages( e.g., keystone).

### Content of the document

* 2016 -> SEV (secure encrypted virtualization) encrypt hardware isolated VMs.
* 2017 -> SEV-ES (encryption state) encrypt register state on hypervisor transitions.
* 2020 -> SEV-SNP (secure nested paging) memory integrity protection against, e.g., data-replay, memory re-mapping, protection of interrupt behavior and some side-channel attacks.

AMD uses a C-bit associated with the physical address to determine whether a page is encrypted or not.

*Availability*: They define hypervisor prerogatives here (the ability to schedule and manage resources).

*Reverse Map Table (RMP)* only owner of a memory page can write to it + ensures a page can only be mapped to one guest at a time + prevent memory remapping with the RMP.

### Reverse Map Table

One entry per Page used by VMs -> tracks owner and access rights.
Relies on physical addresses and checked at the end of table walks.
For VMs, RMP contains the GPA.
They avoid checks on read from the hypervisor.

New CPU instructions to manipulate RMP entries.

### Page validation

New instruction PVALIDATE for the guest to validate changes suggested by the hypervisor, i.e., use a private page.
The goal is for the guest to not validate the same GPA twice.
This gives an injective mapping between GPA and system PA (SPA), i.e., this blocks remapping.

### Page States
8 states in total with marked transitions between them.
E.g., swaps to disk the AMD-SP keeps track of metadata info to validate the reload of the page.


### Virtual Machine Privilege Levels

Guest can divide address space into 4 levels -> it's rings.
Can grant equal or less access to a page to VMPL below.
Checks are added to the page walk.
*VMPLs are per vCPU?*

VMPLs are used for APIC (Advanced Programmable Interrupt Controller).
This allows VMPL0 to emulate APIC.

See figure 8, it looks like a lot of bouncing.

### Interrupt/Exception Protection

2 modes:

1. Restricted Injection: disables virtual interrupt queuing and single exception vector injection.
Said differently, it requires communication between hypervisor and guest to handle the interrupt.
2. Alternat Injection: standard virtual interrupt queuing and injection interfaces.
Leverages the VMSA (encrypted state inside the VM).

The goal is to run a vCPU VMPL0 with the first mode, and others with the second so that VMPL0 can emulate interrupts handling and APIC.

### Rest

The rest is details about attestation, migration etc.
Migration is the most interesting bit -> guest can select migration options.

## Requirements for Virtualization

*date*: 1974

### comments:
1. Has the notion of the VMM prerogative on resource (i.e., revocation).
2. We break the notion of the allocator A in the formal specification (we do not decide, we validate).

### abstract

Formal techniques to derive sufficient conditions for architectures to support virtual machines.

### Concepts

virtual machine: an efficient isolated duplicate of a real machine.
*VMM* virtual machine monitor has 3 roles:
1. provide an environment to programs that is essentially the same as the machine
2. shows at worst minor decreases in speed
3. VMM is in complete control of system resources.

Not necessarily a time-sharing system.

### Model of a third generation Machine

They don't model I/O and interrupts.
Two modes of operation (Supervisor and User)
Finite number of states, with a state:

```
S = <E (executable storage), M (proc mod), P (rip), R (relocation bounds register)>
```

Basically program memory storage, mode, current instruction, and virtual memory.
`<M,P,R>` is program status word (PSW).

### Traps

When a trap occurs, storage is left unchanged except for a given locationt that contains the PSW that trapped.
The next instruction (where to trap) is in E[1].

### Instruction Behavior

distinguishes between supervisor and user instructions.
An instruction that traps in user mode is privileged.

Defines control sensitive instructions -> modifies resources or mode without going through a trap.

Behavior sensitive instruction -> effect depends on the relocation bounds.

### VMM

Dispatcher D -> where things trap.
Allocator A -> decides what system resources need to be provided.
Interpreter I -> emulates instructions.

### Properties
3 properties: efficiency, resource control, equivalence.

```
Theorem 1: a vm can be constructed if the set of sensitive instructions is a subset of the privileged instructions.
```

VM map -> mapping of real state to the virtual one.

```
Theorem 2: recursively virtualizable if (a) virtualizable and (b) a VMM without any timing dependencies can be constructed for it.
```

```
Theorem 3: Hybrid VMM may be constructed for machines in which the set of user sensitive instructions are a subset of the set of privileged instructions. 
```

---

## Nexen

*date:* NDSS 2017 

### Comments:
1. One of the techniques to run everything into ring 0.
It does so by controlling all updates to MMU (kind of what we want to do).
2. Related work and diagrams are interesting.
3. Do a binary scan to detect aligned and non-aligned priv instructions.
4. Xen-slice cannot access VM memory apparently?
5. Interpose on memory updates and imposes invariants.
6. Basically has parts of what we want, but is missing the implementation of negociation protocol and formal verification.

### abstract

Lots of vuln in the hypervisor.
Split Xen into least-privilege compartments and a monitor that handles mmu.
Slices are dedicated small parts of Xen, akin to lightweight process, with private memory and isolated from the rest of the hypervisor.

### design

VM-slice: per VM sandboxed Xen functionalities.
Monitor: Nested MMU virtualization + binary scan of other components.

Global shared service: sounds like an optimization for certain operations.
It hosts the scheduler etc. all logic shared by all VMs.

call-gates ensure the provenance of the call.

monopolizes instructions -> only one instance of a privileged instruction in the monitor.
hide-> unmaps it for the rest of the slices

Monitor does the dispatching of interrupts itself.

---

## Improving Xen Security through Disaggregation

*date:* VEE 2008 

### comments:
1. There is a notion of platform admin being able to extend functionalities in the VMM.
That's an interesting thing to take into account.

### abstract
Xen implies a huge TCB (despite the hypervisor being small).
Take the domain builder and put it into a minimal trusted compartment.

### Introduction
Full-fledge OS -> dom0
Transfered the VM-building functionality into a small trusted VM.
Have a lightweight inter-VM communication mechanism.
They consider the problem of confidentiality and integrity , i.e., the admin can have access to all the VMs.

### Xen arch
Back then, was running guest OS in ring 1.
TODO(aghosn) Check if now it runs in VT-x;
Event channel for cross-VM communications + shared memory regions.
2 mechanisms: grant table interface and direct foreign mappings.
Relies on VM IDs for dest/src.

### Building a new VM
Apparently delegated the task to user-code so that it doesn't blow up the size of the hypervisor.
Due to para-virtualization, they can skip some annoying steps (e.g., 16-bit real mode).
*TCB definition:* The set of components which a subsytem S trusts not to violate the security of S.

They seem to assume that random code can be loaded in Dom0 at the discretion of the admin.
why not rely on measurement?

They have a confidentiality-related notion of privileged instruction -> something that might break its assumption.
Again, they move privileged instructions into another VM.

---

## Nested Kernel

*date:* ASPLOS 15 

### comments:
1. Argument compared to VMM is performance (should be size of TCB though)
2. Interesting point is that compared to VMM, nested kernel has knowledge of the OS semantics.

### abstract
nests a small isolated kernel into a monolithic one to protect updates to memory mappings according to policies.
de-priv untrusted part of the kernel.
Enforces code integrity.

### introduction
nested protection domain into the kernel, that knows about the OS semantics.
Mediates writes to MMU -> write mediation and write-logging.
WP-bit again, and code inspection to remove mmu writes from untrusted parts of kernel.

The rest of the paper is straight-forward.

Details about the implementation can be useful for later (see invariants in the paper).
This can be the base/intersect with what we should formally verify.


---

## CloudVisor

*date:* 2011

### comments

1. This is the main competition.
2. Still just confidential VMs.
3. Do they verify stuff OR NOT?
4. Steal TPM part and design, that's mostly what we want
5. Still exclusive access to pages (we want to support RO as well).
6. Lol -> justification for "it's verifiable" is it's 5K, and an OS with 8K was verified.

### abstract

Protect client stack even from compromised VMM and management VM.
Key is separation of resource management from security protection in virtualization layer.
Seurity monitor underneath VMM with nested virtualization and provides protection to hosted VMs.

### introduction

The design is the same as what we intend to build.
It also interposes on IO to include encryption and integrity protection.
They even use TPMs to attest it.
Built on top of Xen.
Provides confidential VMs basically.

Management VMs are just another part of the CSP stack.

### Motivation and Threat Model

### Goals and approaches
Transparent interposition with nested virtualization.
VM-based memory ownership tracking (which page for which VM)
I/O protection with encryption
Late launch (type 2 to type 1).

They use VT-x tech.
