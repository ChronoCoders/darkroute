# Darkrouter

B2B onion routing infrastructure with cryptographic access control and residential exit IPs.

## What it is

Darkrouter is a managed three-hop circuit routing service for businesses that need to make outbound HTTPS requests from an origin the destination cannot attribute to them. Each request travels through three relay hops before exiting through a sticky residential IP. The destination sees a residential address and nothing that ties the request back to your company.

Access is gated by a blind-signed token. What that buys is specific: no single component, if compromised or compelled, yields a link between a subscription and a traffic flow. It does not make you anonymous to us, and the privacy model below says exactly why.

Typical workloads: ad verification, brand-safety crawling, competitive pricing intelligence, fraud detection probes, security research, and any traffic where the calling infrastructure must remain decoupled from the corporate IP space.

## Privacy model

Three principals see different slices of any request:

- **Authority** knows who you are (your subscription), and how many tokens you were issued in the current epoch. It does not see the unblinded token value, it does not see request bytes or destinations, and it does not know or record which path you chose.
- **Relay nodes** know that a token is cryptographically valid and has not been replayed, plus the previous hop and the next hop. They cannot learn which subscriber a token belongs to.
- **Exit node** sees the destination host and one layer of ciphertext. It does not know the client's identity or IP.

**We operate every component, and that is the limit.** Distributed Systems Labs runs the authority and all three relays. The authority sees your IP when you sign in and fetch tokens. The guard sees your IP when you connect. We can match those two, and no cryptography prevents it. **The service does not claim unlinkability against us.** The separation described above is a property between components: it holds against the compromise or subpoena of any one of them, not against the party that runs them all. Unlinkability against the operator would require relays run by separate parties, which is not what this product is.

What does hold. A relay on its own, without the authority's records, cannot learn which subscriber is generating traffic, because it verifies a token offline and never contacts the authority. Tokens are blind-signed under a key shared by every subscriber in the same epoch, so a token narrows you only to that set, and the set of subscribers active in the same epoch is the anonymity set. With few active subscribers that set is small. That is a property of how many people use the service, not of the cryptography.

One thing you can do about the IP join. Tokens are issued in a single batch once per epoch rather than per connection, so that fetch can come from any egress you choose, independent of the network your traffic later leaves from. Then the address we record at sign-in is not the address the guard sees, and the two no longer share a join key. We cannot enforce or verify this, and the very first fetch on a new subscription has no earlier batch to route through, so it reveals your address once.

## Architecture

| Component | Role |
|---|---|
| Authority | Issues blind tokens, manages subscriptions, and publishes a signed relay registry and epoch key set. It does not choose or record your path. Reached only via Cloudflare Tunnel; no public ingress on the origin host. |
| Guard relay | First hop. Verifies the client's blind token, terminates the client-side TLS, runs the per-hop X25519 key exchange, which is not authenticated against a relay identity, and forwards encrypted traffic to a middle relay. |
| Middle relay | Second hop. Relays opaque bytes between guard and exit. Holds neither the client identity nor the destination. |
| Exit relay | Third hop. Decrypts the innermost layer, validates the destination port against an allowlist, and dials through a Decodo residential dedicated IP. |
| Residential exit | Decodo sticky dedicated IP. The destination sees this IP as the request source. |
| Dashboard | Operator self-service for subscription, key management, circuit history, and usage. |

All relay hops run on port 443 with real Let's Encrypt certificates obtained via TLS-ALPN-01. Inter-relay traffic is itself TLS with verified hostnames, so a passive observer of any single hop sees only HTTPS to a darkrouter hostname.

## Client integration

The product surface is a SOCKS5 daemon plus a Rust SDK. A typical integration looks like:

1. Sign up through the dashboard, complete payment, and wait for approval. Approval is manual.
2. There is no access key to copy from the dashboard. The daemon obtains tokens itself: give it your subscriber credentials and it signs in, requests blind-signed tokens, and selects its own path.
3. Put those credentials in the daemon's environment (`AUTHORITY_URL`, `CLIENT_EMAIL`, `CLIENT_PASSWORD`, `SOCKS5_BIND`) and run the daemon on the host that needs to make outbound requests.
4. Point your existing HTTP client at the local SOCKS5 endpoint. Every outbound request transparently builds a fresh three-hop circuit and exits through a residential IP.

The Rust SDK is also exposed directly for applications that prefer in-process integration without the SOCKS5 hop. Both surfaces produce circuits that are functionally identical.

## Stack

- **Authority**: Go, PostgreSQL, JWT sessions, Argon2id password hashing
- **Relay**: Rust, tokio, rustls, rustls-acme, tokio-socks, rsa and num-bigint for blind token verification
- **Shared wire protocol**: Rust, x25519-dalek, hkdf, aes-gcm
- **Client SDK and daemon**: Rust, tokio, rustls, rsa and num-bigint-dig for the blind signature
- **Dashboard**: Next.js 15 (App Router), shadcn/ui

## Self-hosting

Not supported. Darkrouter runs as managed infrastructure on operator-controlled hosts. The relay fleet, authority, residential exit IPs, and certificate lifecycle are operated by Distributed Systems Labs. Source is published for review under the BSL terms below, not for independent deployment.

If you need a private deployment for compliance reasons, contact us.

## Security model

The authoritative specification defines the cryptographic primitives, the principals and their trust boundaries, the blind-token protocol step by step, and an explicit list of what the system does not protect against. It is not published.

The protocol is being rebuilt against a revised security model that is not published, and this README describes the current implementation rather than that target.

For vulnerability disclosure, see [SECURITY.md](SECURITY.md).

## License

Business Source License 1.1. The Change Date is 2029-05-23, after which the Licensed Work converts to Apache License 2.0. See [LICENSE](LICENSE) for the full terms.
