# Quantus Witness Integration

Quantus is an independently deployed signed observation service at `https://quantus.nexinus.net`. It is registered as `QUANTUS` with protocol `QUANTUS_WITNESS_STATUS/v1`.

Quantus is not Tesseract-A Core, Tesseract Mirror, Tesseract-Terminus, Archangel, or VALKYRIE. It does not grant authority, admit governance mutations, adjudicate disputes, or make legal-effect determinations.

## Verification

The operator-initiated verifier reads `GET /v1/health` and verifies:

- schema `QUANTUS_WITNESS_STATUS/v1`;
- service `QUANTUS_WITNESS_CONSOLE`;
- node ID `QUANTUS`;
- status `READY`;
- Ed25519 algorithm and 32-byte public key;
- pinned SPKI SHA-256 fingerprint;
- canonical payload hash;
- Ed25519 signature;
- review boundary `OBSERVATION_ONLY_NOT_A_LEGAL_EFFECT_DETERMINATION`.

`HEAD` remains a reachability observation only. It is not sufficient for witness verification.

The registered SPKI public-key fingerprint is:

```text
c3e9568197203345e7094734515fd02e1a2ddfe3606e282541027d2bda70e9b7
```

The raw public key (hex) is recorded separately in `expected-identity-hashes.json` as `publicKeyHex`.

No ATMOS manifest payload or artifact hash is claimed for Quantus until the operator supplies and measures those artifacts. Those fields remain `null` by design.

## Operator boundary

Run network verification only with:

```sh
ATMOS_ALLOW_NETWORK=1 \
ATMOS_AUTHORIZED_BY='operator identity' \
ATMOS_AUTHORIZATION_REFERENCE='operator-issued reference' \
node atmos-sync-all.mjs
```

The script writes a receipt under `verification-receipts/quantus.observation.json`. No retry or remote mutation is performed.
