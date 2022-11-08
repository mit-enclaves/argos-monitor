# Terminology used in Tyche

---

## Monitor

Tyche is a security monitor, i.e., a piece of software that executes at the highest level of privilege and is responsible for providing memory isolation guarantees.
The monitor implements trust domains and tracks the associated set of resources and access rights available to them.
The monitor does not perform any resource management, i.e., it does not select which resources are allocated to whom and is not involved in scheduling.

**abstractions provided:** Trust domains, memory regions

---

## Hypervisor

A hypervisor, either type 1 or type 2, allocates, loads, and schedules virtual machines.
A hypervisor, similar to an OS, usually conflates management of resources and the isolation of allocated resources.
The hypervisor can further supply higher level abstractions such as virtual devices (e.g., network and disk).

**abstractions provided:** virtual machines, virtual devices.

---

## Trust Domain

---

**Monitor Call:**

---

**Enclave:**

---

**Confidential VM:**

---

**Sandbox:**
