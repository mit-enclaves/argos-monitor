# Motivation/Introduction

In the past decade, the advent of Cloud Computing lead to an increased focus on Confidential Computing solutions.
While advantageous when it comes to rapid deployment, scaling, and fault-tolerance, relying on cloud service requires trusting a third-party with potentially unrestricted access to one's software stack.
This stack includes private intellectual property as well as sensitive customer data. 
Cloud tenants therefore need to trust service providers and expect legally-binding confidentiality and intergrity guarantees.

On the other hand, service providers have an incentive to embedded confidential computing solutions in the core of their management services.
First, following the basic principle of least privilege, CSP do not need to, and definitely should not, have any visibility into their client's workloads.
Second, being able to provide strong confidentiality guarantees would allow them to extend their services to sensitive domains with stringent requirements, e.g., medical or defense fields.
Third, it improves their overall security as even a compromised hypervisor should not be able to access a tenant's data.

Unfortunately, so far, confidential computing is the exception rather than the norm.
Different service providers offer a variety of solutions ranging from software confidential environments to hardware enclaves or confidential VMs. 
The heterogeneity of solutions is a curse rather than advantage and is in part responsible for their slow adoption by end-users.
Porting an existing application to one of these platforms does not necessarily work out-of-the-box.
Applications need to be adapted to run inside a confidential environment, might suffer performance degradation, or rely on non-trivial additional services, e.g., to support attestation.
From the client's perspective, porting an application to a specific confidential solution is a huge effort with the downside of potentially trapping them into a particular service provider or hardware technology.
Several projects[cite anjuna, open-enclave] attempted to provide a uniform framework compatible with a set of technologies but, so far, none of them can claim a complete victory on that front.

Existing confidential computing solutions usual differ according two dimensions: 1) the set of guarantees provided by the hardware and 2) the programming abstraction they offer to clients.
When it comes to hardware support, technologies usually differ based on whether confidential environments require a physical split of resources at boot time to distinguish between confidential and non-confidential environments, the privilege levels and more generally the set of instructions supported within the confidential environment, whether memory is encrypted, and integrity guarantees.
When it comes to the second dimension, related work provides solutions that range from programming language abstractions to full operating systems running inside a virtual machine, and include almost anything in-between (e.g., processes, containers, library operating systems, unikernels, lambda frameworks, etc.). 

Both research and industry have been bogged down by the extensive exploration of both dimensions in the recent years.
This heterogeneity of solutions makes confidential computing hard to define and solutions are difficult to compare or standardize.
If experts have a hard time agreeing on what confidential computing actually means, or rather if we allow the same term to be reused in dissimilar settings, how do we expect users to adopt any of these solutions?

In this paper, we approach the problem of confidential computing from a system design point of view.
Rather than bluntly accepting hardware vendors solutions, we set aside existing mechanisms and hardware features and focus on defining the problem of confidential computing in a system design setting.

We claim that, from a system design point of view, the problem of providing confidential computing reduces to decoupling resource management from access configuration.
For historical reasons, resource management and access control have been conflated and delegated to a single entity.
We believe this can be remedied without extensive modifications to existing software stacks and without fancy new hardware features.
A principled system design approach is sufficient to provide an efficient solution.

We describe our design as an extension to the well-known Popek & Goldberg requirements for virtualization and show how these simple extensions satisfy our definition of confidential computing.
In the process, we focus on access to memory resources but believe our approach could be extended to any form of resource.
For memory, we show that our approach reduces the problem of providing confidential memory to basic memory isolation and propose a unified API.

This paper then introduces Tyche, a security monitor implementation of our design in Rust, that goes beyond confidential computing.
Tyche's focus is not limited to confidential environments but rather provides a general framework for resource sharing between various trust domains.
As such, Tyche not only allow to replace confidential computing technologies[cite all of them], but also intra-address space isolation mechanisms, both hardware (e.g., Intel MPK) and software (e.g., LWC) and to seemlessly combine/nest them.
It further provides a framework to explore how the same principle can be applied to other resources, such as the network of the CPU.

For the sake of our argument, we focus on a pure software implementation that only leverages commonly available hardware features.
This does not, however, imply that we strongly believe everything should be done in software or that there is no benefit to offloading some of the work to new hardware.
We rather protest against the fact that recent confidential hardware extension have trapped us into rigid programming models, ask for a redistribution of prerogatives based on a system re-design, and highlight areas where hardware could be leveraged to do what it does better than software: make things run fast.


