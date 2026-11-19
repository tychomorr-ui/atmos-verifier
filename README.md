# ATMOS verifier

This is a public, read-only verification kit. It contains no private keys or credentials. The verifier runs **offline by default**; network probes require explicit opt-in and operator attribution. Synchronization uses GET only, does not follow redirects, and does not POST.

## Roles and naming

- **Archangel** is the conductor and control plane.
- **Quantus Witness Console** is an independent witness at https://quantus.nexinus.net. It is not Tesseract-Terminus. An observation, including a signed observation, is not verification of its contents or authority.
- **Tesseract-Terminus** is the sovereign provenance console at https://universaltruth.life.
- **Tesseract Mirror** is at https://tesseract.nexinus.net. It is distinct from **Tesseract-A Core**, the verifier. The Core URL is not established here.

`node-declarations.json` distinguishes this unsigned service catalog from legacy signed records. The existing `TESSERACT-A` manifest historically labels itself “Tesseract Mirror”; that label **does not establish** that its pinned key is the new Mirror identity or the Core identity. The mapping remains unresolved. Similarly, the legacy `TESSERACT-TERMINUS` manifest and pin name the historical https://terminus.nexinus.net target; neither is silently assigned to the present sovereign console. Existing legacy probes continue to target their original declared URLs and any `VERIFIED` result applies only to that legacy record, not to an unestablished current-service mapping.

A migration requires operator-verified identity and endpoint evidence, an explicit signed mapping or new enrollment under the applicable governance process, separately reviewed pin changes where appropriate, and a known Core URL before it can be probed. Preserve historical signed artifacts and pins; do not rewrite or re-sign them to make the names agree. The service catalog alone is not an identity enrollment. The local governance admission guard reserves `QUANTUS`, `TESSERACT-MIRROR`, and `TESSERACT-A-CORE` against accidental admission as unknown IDs; this neither enrolls keys nor resolves a mapping. No governance document or deployment is changed by that local guard.

## Run checks

```bash
# Eleven existing signed-manifest checks plus an unprobed Quantus entry; no network.
node ./atmos-sync-all.mjs

# Explicit operator-authorized GET probes.
ATMOS_ALLOW_NETWORK=1 ATMOS_AUTHORIZED_BY="$(whoami)" node ./atmos-sync-all.mjs

# Optional: independently obtain and verify the Quantus operator's raw Ed25519
# public key out of band, then provide its 64 hexadecimal characters.
ATMOS_ALLOW_NETWORK=1 ATMOS_AUTHORIZED_BY="$(whoami)" \
  ATMOS_QUANTUS_PINNED_PUBLIC_KEY='<independently-verified-raw-ed25519-public-key-hex>' \
  node ./atmos-sync-all.mjs

# Offline and simulated-network tests (Python 3 and Node.js 20+ required).
node --test tests/verifier.test.mjs
```

The key placeholder is not an enrolled key. **Never copy a key from the response being checked and treat it as trusted.** The repository already records a Quantus raw key and SPKI fingerprint from an operator-supplied signed observation; their independent provenance is not established here. Without an independently supplied key, a matching signed response is `WITNESS_CANDIDATE_SIGNATURE_VALID_PIN_UNCONFIRMED`, not verified; with no valid recorded candidate it is `WITNESS_PIN_NOT_CONFIGURED`. A malformed pin, wrong key, wrong node/schema/service, invalid signature or hash, or stale/future observation cannot establish a trusted witness status. The `publicKey` in the response must match the supplied or recorded raw key. Quantus's Python producer signs compact, sorted UTF-8 JSON after removing exactly `payloadHash`, `publicKey`, `signatureAlgorithm`, and `signature`; its SHA-256 hash is checked as well. The adapter preserves wire numeric tokens, including `420448.0`, and Python Unicode code-point ordering. A proxy that rewrites numeric representations can cause safe rejection even if their mathematical values are equal.

Quantus's freshness defaults to a maximum age of 300 seconds and future clock skew of 30 seconds, in `node-declarations.json`. The adapter permits stricter values but rejects larger windows. A trustworthy local clock is required. Freshness limits replay age but does **not** prevent replay within the allowed window; there is no nonce or replay cache. Both `READY` and `DEGRADED` can be authentically reported; `reportedStatus` states which one was signed and neither proves the underlying measurements are true.

A successful operator-pinned and fresh Quantus signature is reported as `WITNESS_STATUS_SIGNATURE_VALID_ARTIFACT_UNBOUND`, **not** `VERIFIED`. It has no enrolled signed manifest or pinned artifact binding in this repository. This update does not invent or enroll a new Quantus key, manifest, or artifact hash. `WITNESS_NOT_PROBED`, `WITNESS_CANDIDATE_SIGNATURE_VALID_PIN_UNCONFIRMED`, `WITNESS_PIN_NOT_CONFIGURED`, `WITNESS_PIN_INVALID`, `WITNESS_STATUS_UNTRUSTED`, `WITNESS_STATUS_NOT_PUBLISHED`, and `PROBE_FAILED` distinguish other outcomes. Reports and per-node receipts are written locally to `atmos-sync-report.json` and `verification-receipts/` with restrictive file permissions.

## Existing manifest verification

For the eleven legacy signed records, `VERIFIED` requires a valid local signature against the independently pinned public-key fingerprint **and** manifest payload hash, the same complete signed manifest served by the endpoint with the expected node ID and URL, and a valid signed health document bound to the independently pinned artifact hash. A 2xx response alone is not enough. A self-reported manifest hash and public key are insufficient: the served manifest's content and signature must verify against the pins. A legacy `VERIFIED` result says nothing about unresolved new-service mappings described above.

The legacy health adapter does not check freshness or maintain a replay cache. Its `VERIFIED` label therefore means only the binding checks above, **not** a fresh liveness guarantee or replay-resistant proof. Reports and legacy receipts explicitly carry `freshness: UNCHECKED` and `replayProtection: NONE`. Apply separate freshness and replay controls before using it for a higher-assurance gate.

The original pins and signed manifests remain unchanged. The prior 28 October 2026 report of eleven `VERIFIED` was historical, not a current guarantee. KEIRA, VALKYRIE, and ARCHANGEL bind measured running files; the other eight pins bind published identity artifacts. That distinction is in `expected-identity-hashes.json` and is not a claim that historical applications have moved.

## Health paths

Each node can configure an ordered `healthPaths` list. The allowed paths are `/health`, `/v1/health`, `/v1/status`, and `/.well-known/atmos-health.json`. Legacy nodes default to `/health`, `/v1/health`, then `/.well-known/atmos-health.json`; Quantus defaults to `/v1/health`, `/v1/status`, then `/.well-known/atmos-health.json`. Quantus currently publishes `/v1/health` and `/v1/status`; the well-known path is supported if configured and actually served, not asserted to exist there.

Paths are tried in order **only after HTTP 404 or 410**. The first other result is final: a 200 with invalid JSON, hash, signature, key, or timestamp cannot fall back to a later response to gain trust. Redirects, other HTTP errors, timeouts, oversized responses, and network failures also stop selection. Each response is streamed with a 1 MiB limit. A health document must have HTTP 200. Receipts record every attempted path and the selected path. No path selection changes the existing manifest/artifact trust requirements.

## Separate governance proof tools

The existing `prove-governance-noop.mjs` and `prove-governance-admit.mjs` are separate governance tools that submit POST requests. They are not run by the verifier or its tests, and are not required for witness verification. Their existing signed governance document and historical artifacts are unchanged.
