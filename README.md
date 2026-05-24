# darkrouter

B2B onion routing infrastructure with cryptographic access control and residential exit IPs.

## What it is

darkrouter is a managed three-hop circuit routing service for businesses that need to make outbound HTTPS requests from an unattributable origin. Each request travels through three independently operated relay nodes before exiting through a sticky residential IP. The path between the client and the destination cannot be reconstructed from any single node's logs.

Access is gated by a blind-signed token, so the operator that authorized your circuit cannot link your individual requests back to your subscription.

Typical workloads: ad verification, brand-safety crawling, competitive pricing intelligence, fraud detection probes, security research, and any traffic where the calling infrastructure must remain decoupled from the corporate IP space.

## Privacy model

Three principals see different slices of any request:

- **Authority** knows who you are (your subscription) and that you were issued some token. It does not see the unblinded token value, and it does not see request bytes or destinations.
- **Relay nodes** know the cryptographic validity of a token, the previous hop, and the next hop. They do not know which subscriber the token belongs to and they do not see beyond their own layer of the encrypted envelope.
- **Exit node** sees the destination host and one layer of ciphertext. It does not know the client's identity or IP.

The unlinkability between subscriber and traffic flow is built on a Chaum blind RSA signature: the authority signs a blinded message it never sees in unblinded form, the client unblinds the signature locally, and relays verify the signature against the authority's public key without contacting the authority. The full threat model and trust boundaries are available on request.

## Architecture

| Component | Role |
|---|---|
| Authority | Issues blind tokens, assigns circuits, manages subscriptions, publishes the relay registry. Reached only via Cloudflare Tunnel; no public ingress on the origin host. |
| Guard relay | First hop. Verifies the client's blind token, terminates the client-side TLS, runs the per-hop ECDH handshake, forwards encrypted traffic to a middle relay. |
| Middle relay | Second hop. Relays opaque bytes between guard and exit. Holds neither the client identity nor the destination. |
| Exit relay | Third hop. Decrypts the innermost layer, validates the destination port against an allowlist, and dials through a Decodo residential dedicated IP. |
| Residential exit | Decodo sticky dedicated IP. The destination sees this IP as the request source. |
| Dashboard | Operator self-service for subscription, key management, circuit history, and usage. |

All relay hops run on port 443 with real Let's Encrypt certificates obtained via TLS-ALPN-01. Inter-relay traffic is itself TLS with verified hostnames, so a passive observer of any single hop sees only HTTPS to a darkrouter hostname.

## Client integration

The product surface is a SOCKS5 daemon plus a Rust SDK. A typical integration looks like:

1. Sign up through the dashboard, complete payment, and wait for approval. Approval is manual.
2. Issue a long-lived access key from the dashboard.
3. Drop the key into the daemon's environment (`AUTHORITY_URL`, `CLIENT_EMAIL`, `CLIENT_PASSWORD`, `SOCKS5_BIND`) and run the daemon on the host that needs to make outbound requests.
4. Point your existing HTTP client at the local SOCKS5 endpoint. Every outbound request transparently builds a fresh three-hop circuit and exits through a residential IP.

The Rust SDK is also exposed directly for applications that prefer in-process integration without the SOCKS5 hop. Both surfaces produce circuits that are functionally identical.

## Stack

- **Authority** — Go, PostgreSQL, JWT sessions, Argon2id password hashing
- **Relay** — Rust, tokio, rustls, rustls-acme, tokio-socks
- **Client SDK and daemon** — Rust, tokio, rustls
- **Dashboard** — Next.js 15 (App Router), shadcn/ui

## Self-hosting

Not supported. darkrouter runs as managed infrastructure on operator-controlled hosts. The relay fleet, authority, residential exit IPs, and certificate lifecycle are operated by Distributed Systems Labs. Source is published for review under the BSL terms below, not for independent deployment.

If you need a private deployment for compliance reasons, contact us.

## Security model

The authoritative specification defines the cryptographic primitives, the principals and their trust boundaries, the blind-token protocol step by step, and an explicit list of what the system does not protect against. The full threat model and trust boundaries are available on request.

For vulnerability disclosure, see [SECURITY.md](SECURITY.md).

## License

Business Source License 1.1. The Change Date is 2029-05-23, after which the Licensed Work converts to Apache License 2.0. See [LICENSE](LICENSE) for the full terms.
