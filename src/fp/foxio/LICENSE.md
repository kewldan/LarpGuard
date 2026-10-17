# JA4+ methods (FoxIO License 1.1)

This directory implements JA4T (TCP) and JA4H (HTTP) from the JA4+ suite by
FoxIO, LLC. These methods are covered by the FoxIO License 1.1
(https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md): free for use
by an organization to protect its own systems, but monetizing them (selling a
product or service that uses them) requires a separate license from FoxIO.

JA4 itself (TLS client fingerprint, `src/fp/ja4.cc`) is BSD 3-Clause and is
not part of this directory.

Build without this code: `-DBOT_SHIELD_FOXIO=OFF`. The gateway then emits its
own TCP and HTTP fingerprints only (`src/fp/tcp_syn.h`,
`src/fp/http_fingerprint.h`), which carry no such restriction.
