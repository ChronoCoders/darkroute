# QuietHop

B2B onion routing infrastructure with cryptographic access control and residential exit IPs.

## What it is

QuietHop is a managed three-hop circuit routing service for businesses that need to make outbound HTTPS requests from an origin the destination cannot attribute to them. Each request travels through three relay hops before exiting through a sticky residential IP. The destination sees a residential address and nothing that ties the request back to your company.

Access is gated by a blind-signed token, so a relay can check that a request is paid for without learning which subscriber sent it. It does not make you anonymous to us, and the privacy model below says exactly what holds today and what does not.

Typical workloads: ad verification, brand-safety crawling, competitive pricing intelligence, fraud detection probes, security research, and any traffic where the calling infrastructure must remain decoupled from the corporate IP space.

## Privacy model

This section describes the service as it works today. A revised protocol is in progress and is not described here.

Three principals see different slices of any request:

- **Authority** knows who you are, because you sign in with credentials and we bill you. It signs your blind token without seeing the token value you later present, and it keeps a count of how many tokens you were issued rather than the values themselves. It also chooses the three relays for each of your circuits and records that choice against your subscriber id. It never sees request bytes or destinations.
- **Relay nodes** know that a token carries a valid signature and has not been replayed, plus the previous hop and the next hop. A relay checks the signature offline and never contacts the authority, so a relay on its own does not learn which subscriber a token belongs to.
- **Exit node** sees the destination host and the innermost layer of plaintext. It does not see your address.

What holds. The destination cannot attribute the request to you, which is the property the product is sold on. A relay taken on its own, without the authority's records, cannot tell which subscriber it is carrying.

What does not hold. The authority holds both your identity and the path it chose for you, in its own database, so the authority on its own can link a subscription to the relays that carried it. Blinding the token does not change that, because the join happens in tables beside the token rather than through it. Closing that join is part of the revised protocol and is not in the code today.

**Who operates the relays.** Distributed Systems Labs runs the authority and all three relays today, and that is the initial stage of operation rather than the design. While one party runs every component, that party sees your address when you sign in and again when your client connects to the guard, and it can match the two. No cryptography prevents it, so at this stage the service does not claim unlinkability against us.

The network is built for relays run by several independent operators, each a separate company under contract. On a path whose three hops belong to three different operators, linking your subscription to your traffic needs all three of them to cooperate or to be compelled, rather than one company reading two of its own tables. Each circuit will report how many distinct operators it crossed, so you can see which guarantee a given circuit carries instead of taking our word for the stage we are in. Customers do not operate relays.

## Architecture

| Component | Role |
|---|---|
| Authority | Issues blind tokens, manages subscriptions, and selects and records the three relays of each circuit. Reached only through a Cloudflare Tunnel, with no public ingress on the origin host. |
| Guard relay | First hop. Verifies the client's blind token, terminates the client-side TLS, runs the per-hop X25519 key exchange, which is not authenticated against a relay identity, and forwards encrypted traffic to a middle relay. |
| Middle relay | Second hop. Relays opaque bytes between guard and exit. Holds neither the client identity nor the destination. |
| Exit relay | Third hop. Decrypts the innermost layer, validates the destination port against an allowlist, and dials through a Decodo residential dedicated IP. |
| Residential exit | Decodo sticky dedicated IP. The destination sees this IP as the request source. |
| Dashboard | Operator self-service for subscription, key management, circuit history, and usage. |

All relay hops run on port 443 with real Let's Encrypt certificates obtained via TLS-ALPN-01. Inter-relay traffic is itself TLS with verified hostnames, so a passive observer of any single hop sees only HTTPS to a QuietHop hostname.

## Client integration

The product surface is a SOCKS5 daemon plus a Rust SDK. A typical integration looks like:

1. Sign up through the dashboard, complete payment, and wait for approval. Approval is manual.
2. There is no access key to copy from the dashboard. The daemon obtains tokens itself. Give it your subscriber credentials and it signs in, requests a blind-signed token, and asks the authority for a circuit.
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

Not supported. QuietHop runs as managed infrastructure on operator-controlled hosts. The authority, the relay fleet, the residential exit IPs and the certificate lifecycle are run by Distributed Systems Labs today, and relays will also be run by contracted operators as the network grows. Customers do not run relays in either case. Source is published for review under the BSL terms below, not for independent deployment.

If you need a private deployment for compliance reasons, contact us.

## Security model

The authoritative specification defines the cryptographic primitives, the principals and their trust boundaries, the blind-token protocol step by step, and an explicit list of what the system does not protect against. It is not published.

The protocol is being rebuilt against a revised security model that is not published, and this README describes the current implementation rather than that target.

For vulnerability disclosure, see [SECURITY.md](SECURITY.md).

## License

Business Source License 1.1. The Change Date is 2029-05-23, after which the Licensed Work converts to Apache License 2.0. See [LICENSE](LICENSE) for the full terms.
