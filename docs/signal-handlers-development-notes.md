# Signal Handling in Hyperlight

Hyperlight registers custom signal handlers to intercept and manage specific signals, primarily `SIGSYS` and `SIGRTMIN`. Here's an overview of the registration process:
- **Preserving Old Handlers**: When registering a new signal handler, Hyperlight first retrieves and stores the existing handler using `OnceCell`. This allows Hyperlight to delegate signals to the original handler if necessary.
-  **Custom Handlers**:
  - **`SIGSYS` Handler**: Captures disallowed syscalls enforced by seccomp. If the signal originates from a hyperlight thread, Hyperlight logs the syscall details. Otherwise, it delegates the signal to the previously registered handler. 
  - **`SIGRTMIN` Handler**: Utilized for inter-thread signaling, such as execution cancellation. Similar to SIGSYS, it distinguishes between application and non-hyperlight threads to determine how to handle the signal.
- **Thread Differentiation**: Hyperlight uses thread-local storage (IS_HYPERLIGHT_THREAD) to identify whether the current thread is a hyperlight thread. This distinction ensures that signals are handled appropriately based on the thread's role.

## Potential Issues and Considerations

### Handler Invalidation

**Issue**: After Hyperlight registers its custom signal handler and preserves the `old_handler`, if the host or another component modifies the signal handler for the same signal, it can lead to:
    - **Invalidation of `old_handler`**: The stored old_handler reference may no longer point to a valid handler, causing undefined behavior when Hyperlight attempts to delegate signals.
    - **Loss of Custom Handling**: Hyperlight's custom handler might not be invoked as expected, disrupting its ability to enforce syscall restrictions or manage inter-thread signals.

