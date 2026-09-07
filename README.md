# unidpp-issuer

The UniDPP passport lifecycle issuer service. The libraries prove the
model; this service proves the system: it lets an operator run a
passport end-to-end and a verifier replay every check offline against
the published anchors.

See `TODO.impl/10-remaining-tasks-definitive.md` item 10. Apache-2.0.

## What it does

- creates passports (identity, type ref, **config vector**, capability
  class → passport id + empty log);
- appends typed events (server-signed with the keyring's Ed25519 key →
  `TrustMarker::Attested`); illegal status transitions are rejected
  (invariant I6 — the store enforces both the abstract `from → to`
  legality and the `from == current-status` state-machine guard);
- mints Tier-A offline packs with a **real ECDSA-P256 (RFC 6979)
  signature** via `unidpp-signatif` (the computed suite that rides the
  core's `ecdsa-p256 | sm2 | ml-dsa-*` carrier frame — Ed25519 has no
  carrier slot, the documented deviation lives in
  `unidpp-signatif::sign`) and QR-budget enforcement (over-budget →
  413, never truncates);
- serves the full passport view (core + manifest + log head) — the
  `unidpp/passport@1` document is exactly the format the
  `unidpp` CLI binary reads and writes;
- runs the **full-pipeline verdict + coverage** (`GET /passports/{id}/verdict`):
  the core `VerdictBuilder` over the authoritative log, a Tier-A pack
  pass through `unidpp-cli`'s `verify_pack`, the server-side
  re-verification of every recorded event signature against the
  keyring's Ed25519 anchor, and config-vector resolution against the
  locally registered profiles;
- journals every mutation to an append-only JSONL file (replayed on
  start);
- forwards admin profile registrations and applicability bindings to a
  `unidpp-registry` instance when one is configured and reachable —
  fixtures are journaled locally otherwise;
- serves the public anchors a verifier pins (`GET /keyring`) — keys are
  **seeded-dev mode** (deterministic from `UNIDPP_ISSUER_SEED`) or
  **env-key mode** (real hex seeds from `UNIDPP_ISSUER_EVENT_SEED` +
  `UNIDPP_ISSUER_PACK_SEED`, production only).

## Surface

| endpoint | purpose |
|---|---|
| `POST /passports` | create (identity, type ref, config vector, capability class) |
| `POST /passports/{id}/events` | append a typed event (server-signed → attested); rejects illegal status transitions (I6) |
| `POST /passports/{id}/pack` | mint the Tier-A pack with real signature and QR budget enforcement |
| `GET /passports/{id}?at=` | core + manifest + log head (CLI-compatible document) |
| `GET /passports/{id}/verdict?at=&max_age=` | full-pipeline verdict + coverage |
| `GET /keyring` | public anchors (event key + pack key) a verifier pins |
| `POST /admin/profiles` | register a profile (forwarded to the registry, fixtures otherwise) |
| `GET /admin/profiles` | locally registered profiles |
| `POST /admin/applicability` | bind a profile to a product type |
| `GET /admin/applicability?product_type=&at=` | in-force bindings |
| `GET /admin/log?limit=&offset=` | append-only audit log |
| `GET /healthz` | liveness |
| `GET /` | discovery |

Conventions (mirroring `unidpp-registry`):

- every response is as-of stamped (`x-as-of` header + `as_of` body field);
- 404 responses are no-information — identical bytes for unknown
  passports (I12 enumeration resistance);
- mutations require a Bearer token when `UNIDPP_ISSUER_ADMIN_TOKEN`
  is set (open in dev mode).

## Configuration (`UNIDPP_ISSUER_*`)

```
UNIDPP_ISSUER_BIND              # default 127.0.0.1:8091
UNIDPP_ISSUER_ADMIN_TOKEN       # optional; bearer token for mutations
UNIDPP_ISSUER_STATE_FILE        # optional; JSONL journal
UNIDPP_ISSUER_REGISTRY_URL      # optional; base URL of unidpp-registry
UNIDPP_ISSUER_REGISTRY_TOKEN    # optional; forwarded to the registry
UNIDPP_ISSUER_SEED              # dev seed override (seeded-dev mode)
UNIDPP_ISSUER_EVENT_SEED        # hex; env-key mode (mandatory for prod)
UNIDPP_ISSUER_PACK_SEED         # hex; env-key mode (mandatory for prod)
UNIDPP_ISSUER_MAX_AGE           # default Tier-A freshness window (secs)
```

## Round-trip with the `unidpp` CLI

The GET response of `/passports/{id}` is a first-class `unidpp/passport@1`
document. `unidpp pack --passport <file> --key <seed>` mints a Tier-A
pack from it, and `unidpp verify <pack> --anchor <hex>` verifies it
against the issuer's `/keyring` anchor. The integration test
`cli_round_trip_issues_packs_and_verifies_offline` drives both the
server- and CLI-minted packs through the real CLI pipeline.

