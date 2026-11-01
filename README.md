# `@hypereum/hvr-dev` — Local In-Memory SCITT Transparency Service

SPDX-License-Identifier: Apache-2.0

`@hypereum/hvr-dev` is a zero-dependency local in-memory SCITT Transparency Service for testing Hivemind Receipts (`.hvr`) offline without network access, tenancy, PostgreSQL, or hardware TEEs.

## Endpoints

- `POST /entries` — Register a signed `COSE_Sign1` statement (or JSON playground payload) and receive an RFC 9162 inclusion receipt + 3-of-5 witness-cosigned checkpoint.
- `GET /entries/:id` — Retrieve a registered transparent statement (`.hvr`).
- `GET /entries/:id/receipt` — Retrieve a fresh RFC 9942 COSE inclusion receipt (`application/scitt-receipt+cose`).
- `GET /checkpoint` — Retrieve the C2SP `tlog-checkpoint` signed note with 5 witness cosignatures.
- `GET /.well-known/transparency-configuration` — SCRAPI discovery metadata and dev trust roots.
- `POST /dev/tamper` — Playground helper that flips a byte in a receipt and runs Class-1 offline verification to demonstrate deterministic tamper detection (`VERDICT: FAILED`).

## Quick Start

```bash
npx tsx packages/hvr-dev/cli.ts --port 8788
```
