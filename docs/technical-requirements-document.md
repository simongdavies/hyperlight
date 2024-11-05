# Hyperlight technical requirements document (TRD) 

In this technical requirements document (TRD), we have the following goals:

- Describe the high-level architecture of Hyperlight
- Provide relevant implementation details
- Provide additional information necessary for assessing the security and threat model of Hyperlight
- Detail the security claims Hyperlight makes

## High-level architecture

At a high level, Hyperlight's architecture is relatively simple. It consists of two primary components:

- Host library: the code that does the following:
  - Creates the Hyperlight VM, called the "sandbox"
  - Configures the VM, vCPU, and virtual registers
  - Configures VM memory
  - Loads the guest binary (see subsequent bullet point) into VM memory
  - Marshals calls to functions (called "guest functions") in the Guest binary inside the VM
  - Dispatches callbacks, called "host functions", from the guest back into the host
- Guest binary: the code that runs inside the Hyperlight sandbox and does the following:
  - Dispatches calls from the host into particular functions inside the guest
  - Marshals calls to host functions

## Relevant implementation details

As indicated in the previous "architecture" section, the two main components, the host and guest, interact in a specific, controlled manner. This section details the guest and host, and focuses on the details the implementation of that interaction.

### Guest binaries

Until this point, we've been using "guest" as an abstract term to indicate some binary to be run inside a Hyperlight sandbox. Because Hyperlight sandboxes only provide a limited set of functionality, guests must be compiled against and linked to all APIs necessary for providing the functionality above. These APIs are provided by our rust or C hyperlight guest libraries.

> While guests may compile against additional libraries (e.g. `libc`), they are not guaranteed to run inside a sandbox, and likely won't.

The Hyperlight sandbox deliberately provides a very limited set of functionality to guest binaries. We expect the most useful guests will execute code inside language interpreters or bytecode-level virtual machines, including Wasm VMs (e.g., [wasmtime](https://github.com/bytecodealliance/wasmtime)). Via this abstraction, we aim to provide functionality the "raw" Hyperlight sandbox does not provide directly. Any further functionality a given guest cannot provide can be provided via host functions.

### Host library

The Hyperlight host library provides a Rust-native API for its users to create and interact with Hyperlight sandboxes. Due to (1) the nature of this project (see the section below on threat modeling for details), and (2) the fact the host library has access to host system resources, we have spent considerable time and energy ensuring the host library has two major features:

- It is memory safe
- It provides a public API that prevents its users from doing unsafe things, using Rust features and other techniques

## Security threat model and guarantees

The set of security guarantees we aim to provide with Hyperlight are as follows:

- All user-level code will, in production builds, be executed within a Hyperlight sandbox backed by a Virtual Machine.
- All Hyperlight sandboxes, in production builds, will be isolated from each other and the host using hypervisor provided Virtual Machines.
- Guest binaries, in production Hyperlight builds, will have no access to the host system beyond VM-mapped memory (e.g., memory the host creates and maps into the system-appropriate VM) and a Hypervisor-provided vCPU. Specifically, a guest cannot request access to additional memory from the host.
- Only host functions that are explicitly made available by the host to a guest are available to the guest, the default state is that the guest has no access to host provided functions.
- If a host provides a guest with such a host function, the guest will never be able to call that host function without explicitly being invoked first. In other words, a guest function must first be called before it can call a host function.
- If a host provides a guest with a host function, the guest will never be able to execute that host function with an argument list of length and types not expected by the host.
