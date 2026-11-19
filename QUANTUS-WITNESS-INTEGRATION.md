# Quantus Witness Integration

Quantus Witness Console is a separate, read-only observation service at `https://quantus.nexinus.net`, identified as `QUANTUS` and using `QUANTUS_WITNESS_STATUS/v1`. It is not Tesseract-A Core, Tesseract Mirror, Tesseract-Terminus, Archangel, or VALKYRIE. It does not grant authority, adjudicate disputes, or establish legal effect. The existing service signs local status; a receipt-ingestion workflow is not established by this repository.

## Verification and trust

An operator-authorized GET probe uses `/v1/health`, with the configured status/health fallbacks described in [README.md](README.md). The verifier checks the schema, service, node ID, status, review boundary, Ed25519 signature, SHA-256 payload hash, public-key match, and bounded timestamp. `READY` and `DEGRADED` can both be authentic signed reports. `HEAD` and HTTP success alone are never sufficient. Freshness does not prevent replay within the accepted window.

The existing `expected-identity-hashes.json` records this Quantus SPKI public-key fingerprint:

```text
c3e9568197203345e7094734515fd02e1a2ddfe3606e282541027d2bda70e9b7
```

The corresponding 32-byte raw key is retained separately as `publicKeyHex`. The record's stated source is an operator-supplied signed observation; it does not itself demonstrate independent verification of the key's provenance. Without an explicitly supplied operator pin, a fresh status matching this recorded candidate is reported as `WITNESS_CANDIDATE_SIGNATURE_VALID_PIN_UNCONFIRMED`, not a trusted identity. Independently confirm the raw Ed25519 public key with the operator out of band, then provide it as `ATMOS_QUANTUS_PINNED_PUBLIC_KEY` as shown in the README. Never use a key taken solely from the response being checked as a trust anchor.

Even with an operator-supplied pin, a valid signature is `WITNESS_STATUS_SIGNATURE_VALID_ARTIFACT_UNBOUND`, not `VERIFIED`: no ATMOS manifest or artifact hash is yet available for Quantus. A signed observation does not prove its content or grant permission.

## Programmatic adapter compatibility

`verifyQuantusWitnessStatus(rawResponseText, expectedSpkiFingerprint, options)` requires the **raw response text**, not a parsed object. Python's signer preserves numeric representations such as `1.0`; parsing and reserializing them in JavaScript can change signed bytes. Older callers that pass a parsed object now receive `RAW_BODY_REQUIRED`. The helper `fetchQuantusWitnessStatus` returns both `raw` and `parsed`, limits responses to 1 MiB, requires HTTPS, performs only GET, and does not follow redirects. The caller is responsible for operator authorization and an independently verified fingerprint.

The batch script writes an observation under `verification-receipts/quantus.observation.json`. It never mutates the remote service, deploys an endpoint, publishes an identity manifest, or enrolls a key.
