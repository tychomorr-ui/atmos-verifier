# ATMOS verifier

Public verification kit for the Nexinus Sovereign Mesh. This repository contains no private keys, PEMs, credentials, or Gate 4 material.

A node is `VERIFIED` only when its live HTTPS endpoint serves the expected public-key fingerprint, the expected signed manifest payload, and a signed health response bound to the expected artifact hash. An HTTP 200 or `HEAD` response is not evidence.

## Check all eleven nodes

```bash
ATMOS_ALLOW_NETWORK=1 ATMOS_AUTHORIZED_BY="$(whoami)" node ./atmos-sync-all.mjs
```

The expected result on 28 October 2026 was 11 `VERIFIED`.

## Check ARCHANGEL's control-plane rejection

The governance document is [https://archangel.nexinus.net/.well-known/atmos-governance.json](https://archangel.nexinus.net/.well-known/atmos-governance.json).

```bash
node ./prove-governance-noop.mjs
```

That generates a throwaway key, submits one signed `NOOP`, and submits the same request again. The first decision must be `ACCEPTED`. The second must be a signed `REJECTED` / `REPLAY`. A `NOOP` changes no node.

```bash
node ./prove-governance-admit.mjs
```

That checks a signed admission, its replay rejection, a second admission of the same node, and rejection of an existing canonical node. Admission does not publish DNS.

## Canonical endpoints

| Node | Endpoint |
|---|---|
| Root-Gate | https://rootgate.nexinus.net |
| Tesseract-Terminus | https://terminus.nexinus.net |
| XinUS-Clarity | https://clarity.nexinus.net |
| Monarch-OS | https://monarch.nexinus.net |
| Tesseract Mirror | https://tesseract.nexinus.net |
| KEIRA | https://keira.nexinus.net |
| VALKYRIE | https://valkyrie.nexinus.net |
| ARCHANGEL | https://archangel.nexinus.net |
| Project Reclaim | https://reclaim-node.nexinus.net |
| IWA-SAGE | https://iwa.nexinus.net |
| Resonate Earth | https://resonate.nexinus.net |

KEIRA, VALKYRIE, and ARCHANGEL bind measured running files. The other eight bind published identity artifacts. That distinction is in `expected-identity-hashes.json` and is not a claim that every historical application has moved.
