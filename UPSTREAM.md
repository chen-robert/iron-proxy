# Vendored upstream provenance

This directory vendors the official IronProxy source with local crypto-scan
security-policy extensions.

- Upstream repository: `https://github.com/ironsh/iron-proxy.git`
- Upstream tag: `v0.49.0`
- Upstream commit: `c8724937fbe109b7fbc6ddb21490e15902b187c0`
- `git archive --format=tar` SHA-256: `2365b98e1ee9e55e3d930e0fecddcf7212b85888f5de93856f2a1b5d163a6787`
- Canonical `git ls-tree -r --full-tree` SHA-256: `e47964d41b43e472533a1c1084549ded73ffea6e6b42afe2423bf33d0cbb1b6d`
- `UPSTREAM_TREE.txt` records every upstream path and Git blob ID for offline
  verification of the complete vendored delta.
- Go dependencies are locked by the unmodified upstream `go.sum`.
- License: Apache-2.0; the complete upstream `LICENSE` is retained.

Files carrying crypto-scan changes contain an explicit modification notice.
The generic `json_rpc` and `request_policy` transforms, their strict
unknown-field config decoding, compiled whole-value RE2 query matching,
exact-port rule support, exact-address hostname-scoped private-address dial
exceptions, and finite downstream listener/handshake deadlines are local
changes.
