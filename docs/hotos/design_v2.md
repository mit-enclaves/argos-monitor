# Background 

This section provides the necessary background to understand the fundamental design flaws that make confidential computing hard to support on modern systems.
It first introduces the terminology that will be used throughout this paper and highlights the distinction we make between management of and access control to resources.
In order to decouple the concepts we present from the architectural details, we adopt the model proposed by Popek & Goldberg for the virtualization requirements and map our terminology to theirs.

This section then shows how, within that model, the problem of confidential computing can be reduced to the ability to decouple management from access control.
It further enumerates the requirements that such a solution must satisfy.

Finally, we propose an extension to the Popek & Goldberg theorem to extend it to confidential computing.

## Terminology

### Management vs. Access control

Any operating system class introduces the notion of separation of mechanisms and policies.
In its original form, it states that no mechanism should dictate or overly restrict the policies that pertain to which operations should be authorized and which resources should be allocated.

Taken slightly differently, this design principle decouples policies from the mechanism in charge of enforcing them.

In this paper, we call management the operation that defines policies.
For lack of a better term, we call access control the mechanism leveraged to enforce the policies.
From these simple definitions, a manager is an entity that decides which policies should be enforced.
We call **client** an entity whose access to resources is subjugated to a separate entity's policies.
We generalize the notion of manager and clients by calling **domain** entities defined by seperate sets of policies that determine which resources are available to them and which operations are permitted.
For example, different user process applications running on top of an operating systems are different client domains, for which the manager domain is the OS. 

Traditionally, the manager is also directly in charge of enforcing its own policies by leveraging an access control mechanism.
This is more easily shown in a simplified model such as the one introduced by Popek & Goldberg.

The requirements for virtualization distinguish between two modes of operation for a virtualizable architecture: user and supervisor.
The paper states that a VMM must be in complete control of the virtualized resources, which is expressed in the theorem as the requirement for sensitive instructions (that can change the resource configuration in the system) to be a subset of the privileged instructions, only available in supervisor mode, where the VMM executes.

Going back to management and access controls, Popek & Goldberg's theorem implies that the access control mechanism must be available only in supervisor mode.

It can sometimes be hard to understand how to apply this theorem to modern systems as it is highly context dependent.
One way to circumvent this difficulty is to focus on identifying 1) which mechanism is used for access control, and 2) who has access to it.
For example, let's consider a traditional commodity operating system running process applications.
The operating system is in supervisor mode, e.g., ring 0, and leverages page tables to control an application's access to memory, which execute in user mode, e.g., ring 3.
The operating system is a manager, as it decides which resource to allocate to each process, based on its own policies.
Now what if the operating system executes inside a virtual machine on top of a hypervisor?
In this enlarged context, the hypervisor is the one executing in supervisor mode, ring 0 root mode, and the access control mechanism for memory is the set of extended page tables.
With hardware-virtualization extensions such as Intel VT-x, modifying the page tables root (cr3) is no longer a privileged operation as it can be performed in non-root mode.

To simplify the discussion, assume for the remainder of this paper that we always consider the largest context when we refer to supervisor and user mode.

## The Problem with Confidential Computing

### Conflating

For historical reasons, the manager is set in the supervisor mode in order to directly leverage the access control mechanism to enforce its own policies.
While this design served us well for several decades, confidential computing highlighted the need for a change.

For confidential computing, the root problem is the conflation of managerial and access control prerogatives within the manager.
In fact, as traditional systems put the manager in supervisor mode, nothing prevents it from transparently granting itself (or other domains) access to a client's sensitive resources.
As a result, confidential computing requires to either introduce a new access control mechanism that cannot be transparently leveraged by the manager, or to restrict its access to the default mechanism. 
The notion of transparency in the change of access control configuration means that the change is not observed by the client. 

### Requirements for a solution

From the Popek & Goldberg theorem, it follows that whatever domain executes within supervisor mode has the unsupervised ability to modify access control configurations.

By definition of the confidential computing problem, the client does not trust its manager with unrestricted access to its resources.
As a result, the manager, e.g., the operating system or hypervisor, cannot execute in supervisor mode.

The manager has the prerogative of coming up with policies in terms of resource allocations and authorized operations.
Specifically, it must be able to decide which resource to expose to a client, and be able to revoke it.

The client, in the context of confidential computing, requires visibility over the management of its resources and operations.
Not only does it need to be able to enumerate them, it also requires a stronger guarantee that some of the resources are exclusively available to him, i.e., they are not shared with any other domain and reclaiming them should not leak sensitive information.
This is however still not enough, any modification to its configuration needs to be made visible.
The exokernel[cite] describes this property as visible resource availability, revocation, and allocation.
We extend it with the notion that resource availability should include allowed operations on the resources and whether or not they are shared with another domain.

Confidentiality and integrity as usually defined by confidential computing solutions are protected by the above client guarantees.
Confidentiality is guaranteed by resource availability and visible revocation.
For memory, for example, a client can guarantee that a given page is not shared with another domain.
Whenever the manager revokes access to the page, the client has the opportunity to, e.g., zero out the page or encrypt and hash its content before it is returned to the manager.
Integrity is derived from resource availability as well, as exclusive access guarantees no other domain can modify the resource transparently.

A valid solution that supports confidential computing must therefore satisfy both the manager and the client's requirements.
The implementation of the solution must execute within supervisor mode.

We define trust as the strong belief, for a domain, that the supervisor mode code guarantees the requirements listed in this section for all domains.

Trust is a relative notion that is hard to define and exists on a spectrum rather than as a binary value.
It is thus hard to come up with a single technique to derive trust. 
For example, one would be inclined to trust some code if it supplied by a trusted source, or if it is open for inspection.
Others might require it to be verified by formal techniques.
However, there is common requirement in all three approaches: the ability to identify what code is running.
This can be be done via an attestation mechanism, i.e., a protocol that supplies an unforgeable measurement of the software deployed. 

A harware root of trust (e.g., a TPM) is one way to measure and attest the software running in supervisor mode.
The measurement must be unforgeable, signed, and should be verifiable by a third party.
This is the generic platform integrity use case of a TPM and is becoming a standard, even on edge devices.

## Popek & Goldberg Extension

### Compatibility with Decoupling

One might think that confidential computing contradicts the Popek & Goldberg theorem; rest assure, it is actually quite the contrary.
In Popek & Goldberg's theorem, the VMM is a hypervisor that executes in supervisor mode and has complete control of virtualized resources.
The authors, however, partition the VMM into three modules: 1) the dispatcher, 2) the allocator, 3) the interpreter(s).

Upon a trap, the dispatcher calls specific functionalities provided by either of the other two modules.
The allocator is a manager that selects resources to allocate to each VM.
The interpreters are VMM routines that execute privileged instructions, which include access control configuration ones.

By definition, a trap yields control to supervisor mode and thus it needs to be implemented in supervisor mode.
The same observation applies to interpreters that require access to privileged instructions.
The allocator, however, does not need to execute within supervisor mode therefore does not have to be trusted.
There is a natural split of a VMM that boots out of the allocator, i.e., the manager, from supervisor mode, just as required in section X. 

Figure Y shows the two approaches next to each other.

### Extended requirement for Confidential Computing

The Popek & Goldberg theorem can be extended with requirements to support confidential computing. 
The previous section shows the necessity to have a root of trust capable of guaranteeing a platform's integrity.
We define attestation as the protocol that supplies a non-forgeable signed measurement of the boot process to a third party that has the ability to validate the signature without any ambiguity.
We specify the following theorem as an extension to the requirements for virtualization:

**Theorem**: A computer that is virtualizable in the sense of the Popek & Goldberg theorem can provide confidential computing if the boot process and the software running in supervisor mode can be measured and attested.

Note that as trust is a relative notion, it is not included in the extension of the theorem.

# Design 

## Monitor 

Let us call the domain that executes within supervisor mode a monitor.
The monitor is the sole domain with the ability to modify access control to resources.
It arbitrates interactions between a manager and a client, while preserving the guarantees described in the previous section for each of them.
From the book *principles of system design: an introduction*, the monitor is a **trusted intermediary** that mediates interactions between mutually distrustful domains.

The monitor does not create policies for resource allocations, it simply enforces them.
Per our list of requirements, the manager is in charge of selecting which resource to allocate and which operation to allow in its client domain.

However, in order to preserve the client's guarantees, the monitor must be able, for any domain, to enumerate its available resources and allowed operations, which includes distinguishing between shared and exclusive resources, provide the client with visibility into any modification applied to them, and prevent leakage through revocation.

## Generalisation

So far, the discussion has showned only the monitor can execute in supervisor mode and needs to be trusted by all domains.
Nothing said so far requires to have a single manager.
Nothing requires a client to have a single manager.

Before going any further, we generalize the notions of manager and clients to better reflect the reality of the world.
Consider the very common case where a hypervisor manages resources for a guest operating that itself manages them for a set of applications.
Now that the notion of a manager is no longer tied down to executing in supervisor mode, we can consider both the hypervisor and the guest operating system to be managers, while both the operating system and the applications are clients. 
This simply requires each of these elements to be considered as separate domains.

This generalization comes at a cost: it requires to introduce a general model to describe resources and allow policies to translate into access control configurations.
This is the role of the next section.

## A Model to Express Resource Management

This section describes a capability system (mechanism) managed by the monitor and used by domains.
This is not a requirement for a valid monitor implementation but rather a convenience to more easily describe the semantics of the design.

A capability is defined as a communicable, unforgeable token of authority that references an object (a resource) associated with access rights (operations). (TODO THIS IS WIKIPEDIA COPY-PASTE, SHOULD IMPROVE)
Operations on capabilities allow managers to implement their policies and the monitor to translate them into valid access configurations.

### Capabilities 

We propose a capability system with mainly two types of capabilities: resource and revocation.

A resource capability represents the ability to perform the specified operations on the associated object.
In our capability system, every resource object has a reference count that tracks how many capabilities apply to it and it is always sufficent to hold a capability to an object to consult its reference count.
We assume an initial state, for any system, where there is only one capability per unit of resource with full access to it. 
Resource capabilities can be split, i.e., consumed, to yield a new pair of capabilities with either the same set of operations as the original one, or any subset of them.
The subset includes the empty set, i.e., a resource capability with no access to the resource.
The reference count of the object is incremented to mirror the number of non-empty resource capabilities. 
A split further generates a revocation capability for the created pair.

A revocation capability references a pair of capabilities, note that we do not specify whether these are resource of revocation ones and explain why later on.
The only operation permitted is a merge, i.e., it consumes the capability and the pair in order to reform the same capability that was split to create them.
In other words, a revocation capability allows to undo a split.
Revocation capabilities cannot be split.

If it helps the reader, a sequence of splits applied to resource capability creates a tree whose nodes are revocation capabilities and leaves are resource ones.
A split replaces a leaf with a revocation node whose children are two new resource capabilities.
A merge on a revocation node deletes its subtree and replaces the node with the original capability whose split created it. 

### Ownership

Capabilities are communicable tokens, i.e., they can be passed between domains.
A domain owns a capability if it holds a reference to the capability.
By design, at any given point, at most one domain can hold a reference to a given capability.

Capabilities can be transfered between domains.
Any domain A that owns a capability X can transfer it to a domain B.
In the process, A loses the reference to X and thus the associated authority while B acquires it.
To satisfy the visible resource allocation, the monitor requires B to acknowledge X before it can start using it.
If B rejects X, X is transferred back to A.

Note that a given domain can own multiple capabilities referencing the same resource.
The authority of the domain over the resource is therefore the union of the authority of all its relevant capabilities.

Ownership of capability is different than ownership of a resource.
A resource R is owned by a domain A if the root capability in the tree that oversees R is owned by A. 
This definition implies that A can own R despite not having access to it.
This property is essential in order to implement confidential memory while preserving the Popek & Goldberg requirement that a hypervisor must be in full control of the virtualized resources.
Note that the second part of the statement is relaxed to only include the set of resources owned by the hypervisor.

While capabilities can only be referenced by one domain at a time, resources can have multiple references pointing to them.
To ensure exclusive access to a resource, a domain needs to consult the reference count associated with the capability's object.

## Trusting the Monitor

Deriving trust in the monitor can be done in two steps: 1) prove that the proposed model preserves the list of requirements, and 2) provide an implementation that correctly implements this model.
For a particular notion of trust, the correctness of the implementation can either rely on extensive code inspection or require formal proofs. 

In this section we focus on the first step: Is our model enough to guarantee section X requirements?

### From the Manager's point of view

### From a Client's point of view


## Going beyond Confidential Computing

The system described in this section is far more general than the limited case of confidential memory.
As demonstrated, it reduces confidential computing to the decoupling of management from access control.
When it comes to particular resources, it allows fine-grained control over resource sharing.
It further decouples exclusive access to a resource from its ownership.
By allowing all domains to act as both clients and managers, while preserving the managerial chain, the monitor decouples management prerogative from hardware privileged modes.
All of these are strong results that allow any form of compartimentalization and nesting of domains. 
It is, for example, possible to implement sandboxing mechanisms on top of this model and combine them with confidential computing guarantees.

By design, the description of the model mentionned resources, without specifying which ones.
This is to allow the system to manage various types of resources, both physical or abstract.
While memory is the main focus of our implementation in the next section, we believe the model can include PCI devices, interrupt handling, the ability to create new domains, establishing communications between domains, and potentially even CPU resources.
Our intuition, that future work will explore, is that the Popek & Goldberg theorem can be generalized to include any resource for which there is an access control mechanism that is solely available in supervisor mode.
