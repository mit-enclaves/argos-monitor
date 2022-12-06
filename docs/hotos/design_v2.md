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

Taken slightly differently, this design principles decouples policies from the mechanism in charge of enforcing them.

In this paper, we call management the operation that consists in defining policies.
For lack of a better term, we call access control the mechanism leveraged to enforce the policies.
From these simple definitions, a manager is an entity that decides which policies should be enforced.
We call **client** an entity whose access to resources is subjugated to a separate entity's policies.
We generalize the notion of manager and clients by calling **domain** entities defined by seperate sets of policies that determine which resources are available to them and which operations are permitted.
For example, different user process applications running on top of an operating systems are different client domains, for which the manager domain is the OS. 

Traditionally, the manager is also directly in charge of enforcing its own policies by leveraging an access control mechanism.
This is more easily shown in a simplified model such as the one introduced by Popek & Goldberg.

The requirements for virtualization distinguish between two modes of operation for a virtualizable architecture: user and supervisor.
The paper states that a VMM must be in complete control of the virtualized resources, which is expressed in the theorem as the requirement for sensitive instructions (that can change the resource configuration in the system) to be a subset of the privilege instructions, only available in supervisor mode, where the VMM executes.

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

One might think that confidential computing contradicts the Popek & Goldberg theorem; rest assure, this is not the case.
The theorem states that the VMM should execute in supervisor mode and have complete control of virtualized resources.
The theorem identifies the VMM as being the entity that can configure the access control mechanism, but not necessarilly the one in charge of policies.
Satisfying confidential computing requirements can be achieved by physically decoupling management from access control, while preserving certain guarantees that we enumerate next.

### Requirements for a solution

From the Popek & Goldberg theorem, it follows that whatever domain executes within supervisor mode must be trusted as it has the unsupervised ability to modify access control configurations.

By definition of the confidential computing problem, the client does not trust its manager with unrestricted access to its resources.
As a result, the manager, e.g., the operating system or hypervisor, cannot execute in supervisor mode.

The manager has the prerogative of coming up with policies in terms of resource allocations and authorized operations.
Specifically, it must be able to decide which resource to expose to a client, and be able to revoke it.

The client, in the context of confidential computing, requires visibility over the management of its resources and operations.
Not only does it need to be able to enumerate them, it also requires a stronger guarantee that some of the resources are exclusively available to him, i.e., they are not shared with any other domain and reclaiming them should not leak sensitive information.
This is however still not enough, any modification to its configuration needs to be made visible.
The exokernel[cite] describes this property as visible resource availability, revocation, and allocation.
We extend it with the notion that resource availability should include allowed operations on the resources and whether or not they are shared with another domain.

A valid solution that supports confidential computing must therefore satisfy both the manager and the client's requirements.
The implementation of the solution must execute within supervisor mode.

Before moving on to the next section that presents our design, we need to clarify one part of our argument.
One might think that we led the reader through a contradiction.
We can summarize our discussion with two predicates:

1) The hypervisor or OS, that traditionally executes within supervisor mode, cannot be trusted.
2) The domain which executes within supervisor mode must be trusted.

There are two ways to satisfy both predicates at once: 1) either derive a way to trust the manager, or 2) boot the manager out of supervisor mode. 

In this section we argued in favor of the second approach by showing that management and access control can be decoupled, while preserving the prerogatives of the manager. 


# Design 

## Monitor 
Let us call the domain that executes within supervisor mode a monitor.
The monitor is the sole domain with the ability to modify access control to resources.
It arbitrates interactions between a manager and a client, while preserving the guarantees described in the previous section for each of them.
From the book *principles of system design: an introduction*, the monitor is a **trusted intermediary** that mediates interactions between mutually distrustful domains.

The monitor does not create policies for resource allocations, it simply enforces them.
Per our list of requirements, the manager is in charge of selecting which resource to allocate and which operation to allow in a client domain.

However, in order to preserve the client's guarantees, the monitor must be able, for any domain, to enumerate its available resources and allowed operations, which includes distinguishing between shared and exclusive resources, provide the client with visibility into any modification applied to them, and prevent leakage through revocation.
For this purpose, we propose to introduce an ownership model over resources, maintained within the monitor.

## Ownership: Grant, Share, Revoke

Assume all resources can be accounted for in non-divisible units controlled independently via the access control mechanism.
For example, with page tables as the access control mechanism, the physical memory can be exposed at the granularity of pages (usually 4KB).

A domain has access to a unit of resource if the access control configuration for this domain permits some operations from the domain on this resource.

A domain has ownership over a unit of resource if it is able to revoke it from any other domain, and no domain has the ability to revoke this resource from it.

A resource is exclusive to a domain if it only appears in the resource configuration of this domain.
A resource is shared if it appears in the resource configuration of more than one domain.

A domain A grants a resource R to another domain B when it gives up access to R and offers a form of access to B for R.
It however retains the ability to revoke B from R.

A domain A shares a resource R with B if it offers a form of access to B for R.
It retains both access and revocation ability over R for B.

Domains cannot grant or share resources they do not have access to.

A domain that owns a resource R can grant itself access to it if and only if the resource was not granted to another domain.

From an implementation point of view, the monitor needs to track how many times a unit of resource is mapped in a configuration, and the grant and share operations performed by the system in order to allow revocations.

These definitions of grant, share, and revocation are more general than what has been described so far as they allow the same domain to act as both a client and a manager for the same unit of resource.
Given a chain of grant and share operations, any domain that wants to claim back a resource or access a granted one needs to trigger a chain of revocations for the remainder of the chain. 


## Establishing Trust

## Extending Popek & Goldberg

## Going beyond Confidential Computing
