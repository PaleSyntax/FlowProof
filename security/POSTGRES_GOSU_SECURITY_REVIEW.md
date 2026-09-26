# PostgreSQL gosu reachability review

The production PostgreSQL reference is pinned to `postgres:16.14-alpine3.24@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777`. Its amd64 manifest is `sha256:7a396fd264a2067788b6551122b50f162bf6136312c7fc9d74381cb92c648382`.

Trivy `0.69.3` reports fifteen fixed HIGH/CRITICAL Go stdlib CVEs in `/usr/local/bin/gosu` (`gosu 1.19`, `go1.24.6`). The normalized complete list and fixed versions are in `postgres-gosu-reachability.json`.

The exact upstream `tianon/gosu` tag `1.19` commit `6456aaa0f3c854d199d0f037f068eb97515b7513` is resolved through `https://proxy.golang.org` as immutable pseudo-version `v0.0.0-20250923190938-6456aaa0f3c8`, with the module and `go.mod` checksums pinned in `postgres-gosu-reachability.json`. Direct VCS access is disabled with `GOVCS=*:off`. A source-mode `govulncheck v1.1.4` scan using `go1.24.6` at symbol level found zero function-reachable findings. Module- or package-level findings without a `trace[].function` do not establish execution reachability. The same result must be reproduced before changing this VEX.

The OpenVEX document is deliberately limited to the exact stdlib PURL, listed CVEs, and image digest. CI validates that digest before passing the document to Trivy. A changed PostgreSQL digest, component/version, missing VEX, or an additional HIGH/CRITICAL CVE fails the aggregate security gate. This is not a `.trivyignore` and it does not waive new findings.

FlowProof owns this derived classification, not PostgreSQL. Each reproduction preserves and revalidates the Go module download metadata, raw govulncheck JSONL, and their SHA-256 bindings before the aggregate gate accepts the VEX. Re-run the exact reachability analysis whenever the image digest, gosu release, Go version, or Trivy finding set changes.
