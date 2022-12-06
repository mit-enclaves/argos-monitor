# Design

## Terminology

This section first introduces a bit of terminology that will be useful for the rest of this paper.
We define 4 terms: 1) a domain, 2) access control mechanism, 3) a manager, 4) a client.

A domain is an entity within a deployed system.
Each domain has access to a subset of the machine's resources and is limited in the type of operations it can perform on them.
For example, one could consider a domain to be a process.
Each process has its own set of page table that define exactly which physical memory regions can be read, written, or executed within the context of the process.
Another example is a virtual machine executing on top of a hypervisor.
The virtual machine has access to a limited portion of the machine's entire physical memory.
In this second case, the set of accessible memory is defined by the extended page-table structure rather than page tables.
This leads to the definition of the second term, access control mechanism.

Access control is the mechanism by which one can limit a domain's access or valid operations on a particular resource.
Valid operations are implicitely described by the access rights to the referenced resource.
For memory, segmentation, page-tables, extended-page tables are access control mechanisms. 
Some access control mechanisms, e.g., the ones cited above, are implemented as a level of indirection that virtualizes resources, i.e., it not only allows restricting access but also renames the attached resources. 

Partially due to CPU architectures, and mostly due to historical reasons, access control configuration is used by a system manager, e.g., an OS or a hypervisor, to expose resources to client domains, e.g., a process or a virtual machine.
By construction, the manager not only decides which resources should be exposed to a client, but also how, and is responsible for configuring the available access control mechanism accordingly.
Here we make the clear distinction between management, i.e., the set of policies and algorithms to decide which resource should be exposed, and the access control, i.e., the mechanism that enforces these policies.

Taking Popek&Goldberg's requirements for virtualization, the manager (in the paper the VMM) must be in complete control of the virtualized resources, i.e., it must be the sole entity able to change the access control mechanism.
The paper defines this mode of execution with the ability to modify access control as supervisor mode.
Instructions that can modify access control have to be a subset of the privileged instructions, only availble in the supervisor mode, for a machine to be virtualizable.
This is the case, for example, when we consider an OS managing a user process's memory via page-tables.
The page-tables can/should only be modified by the operating system and switching the root of a page table is a privileged instruction.
A client, on the other hand, can ask for new resources (e.g., mmap) or voluntarily relinquish the ones it has access to (e.g., munmap).

## The problem

When it comes to confidential computing, the root of the problem is the conflation within a single domain, the manager, of management and access control configuration prerogatives.
The client does not trust the manager to not grant itself (or another domain) access to confidential resources.
A solution to confidential computing should therefore introduce a form of access control that would prevent the manager itself from accessing the resource.
This is, however, only possible if a new access control mechanism is introduced or if the manager relinquishes its access to the default one.
While hardware solutions have focused mainly on the first approach, we decide to explore the second one.


## Trust

The notion of a domain introduced above can be extended to include the notion of trust.
A trust domain is a domain with a uniform trust level.
It is the basic unit of trust in a system.

We say that a domain trusts another with access to a specific subset of its resources if they share some resource and have fixed access rights to it.
Each domain can potentially have exclusive resources, i.e., the guarantee that a resource is not shared with any other domain.
Both statement assume that none of the domains can transparently increase its access rights to either the shared or exclusive resources.
This is at the heart of the problem described above, as the manager domain in current system designs is such that it can transparently modify its own access rights.
Furthermore, this highlights the need to not only track a domain's access rights to a resource, but also track how many domains share a given resource.

Kaashoek et al.(cite principles of system design: an introduction) suggest that one solution for two mutually distrustful entities to cooperate is to introduce a third, trusted, party to arbitrate their interactions.  
This third party is called the trusted intermediary and is trusted by both parties.
This design is very common, one such example is certificate authorities, trusted by both the website and the browser, or the way in which attestation is typically implemented in SGX.(TODO say more).

## Guarantees

In the case of confidential computing, the trusted intermediary should be the only one able to modify a domain's access rights to resources.
The trusted intermediary needs to provide guarantees to both the manager and the client in order to be trusted.

First, the manager's prerogative to allocate, reclaim, or simply revoke resources from a client must be preserved. 
The manager still selects which resource is allocated to a client, it simply does not configure the access control itself.
The manager can still reclaim by force some resource, which we call revocation.

From the client point of view, the trusted intermediary must guarantee that modifications to the client's access rights and resources are visible and do not leak sensitive information.
The exo-kernel paper[cite] describes this property as visible resource availability, revocation, and allocation.
We further extend this notion of visibility to include access rights and resource accountability, i.e., identify for any resource whether it is exclusively accessible by a domain or not.

To bridge the gap with traditional confidential computing, we can define the notions of confidentiality and integrity.
Confidentiality is guaranteed by the ability for the client to enumerate its resources (visible resource availability) and its exclusive access to them (resource accountability).
Integrity as proposed in this system guarantees that as long as a resource is exclusively available to a domain, it cannot be modified by another domain.

For example, the client and manager can agree that a page revocation always succeeds but zeroes out its content before giving it back to the manager.
An alternative is to agree on a trusted routine code procedure that will encrypt and hash the content of the page with a key available only to the client(cite trustvisor?).
The routine needs to be trusted by both parties in order to preserve the ability of the OS to always revoke resources, and by the client as it has access to the data.
This can be implemented in many ways, either directly within the trusted intermediary, or as a measured and verified element inside the client, similar to hyperupcalls.


