# Security assumptions

The prototype assumes the Linux kernel and BPF verifier are trusted, the agent has permission to attach its probes, and policy files are administrator-controlled.

Event loss under sustained load is possible and should be measured. Process names are treated as context rather than identity; stronger rules should combine ancestry, credentials, namespaces, cgroups and file context.

The current version does not claim kernel tamper resistance, complete network visibility or universal container-runtime metadata resolution.
