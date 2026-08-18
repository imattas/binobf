# Security Boundaries

binobf accepts untrusted binary input and produces software-protection transformations only when correctness can be established.

## Included scope

- compiler and object-format research;
- IP-protection transformations;
- conservative metadata and layout changes;
- selected, semantics-preserving IR/code transformations;
- a documented, conventional software-protection VM;
- structural, differential, property, fuzz, and mutation testing;
- external lineage and crash-mapping data for developers.

## Excluded scope

The project will not implement antivirus/EDR bypass, sandbox/debugger/VM/security-product detection, process injection, remote-process manipulation, credential theft, persistence, privilege escalation, syscall hiding, unhooking, scanner-oriented import hiding, runtime payload downloads, malware packing, reflective loading, shellcode loaders, self-deletion, covert execution, code-signing bypass, malformed executable tricks, overlapping/invalid instructions, exception abuse, or parser-differential attacks.

VM features are normal interpreter functionality, not an execution loader. Memory access is VM-local or validated against addresses legitimately supplied by the protected program; remote process memory is outside scope.

Signed input must be detected before rewriting. If a future transformation invalidates a signature, binobf will require explicit user intent, warn clearly, and never claim the old signature remains valid. Driver-signing enforcement is never bypassed.

When required semantic or metadata evidence is absent, the supported behavior is `Skipped` or `Unsupported`, not unsafe guessing.
