#!/usr/bin/env node
import { generateKeyPairSync, sign, verify, createPublicKey } from "node:crypto";
import { canonicalJson, sha256Hex } from "./atmos-canonical.mjs";

const endpoint = process.env.ATMOS_ADMIT_URL || "https://archangel.nexinus.net/governance/admit";
const documentUrl = new URL("/.well-known/atmos-governance.json", endpoint).toString();
const governance = await (await fetch(documentUrl)).json();
const { signature: _signature, payloadHash: _payloadHash, ...unsigned } = governance;
const documentValid = verify(null, Buffer.from(canonicalJson(unsigned)), createPublicKey(governance.publicKeyPem), Buffer.from(governance.signature, "base64"));
if (!documentValid) throw new Error("Governance document signature is invalid");
if (!Array.isArray(governance.accepts) || !governance.accepts.includes("ADMIT")) throw new Error("Governance document does not accept ADMIT");

function signedRequest(action, extra = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const payload = {
    schema: "NEXINUS_ATMOS_GOVERNANCE_REQUEST/v1",
    action,
    nonce: `${action.toLowerCase()}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    requestedAt: "2026-10-28T17:45:00Z",
    publicKeyPem,
    ...extra,
  };
  return { ...payload, signature: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString("base64") };
}

async function post(body) {
  const response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const decision = await response.json();
  const { serviceSignature, ...decisionPayload } = decision;
  const valid = verify(null, Buffer.from(canonicalJson(decisionPayload)), createPublicKey(governance.publicKeyPem), Buffer.from(serviceSignature, "base64"));
  return { status: response.status, decision: decision.decision, reason: decision.reason, valid };
}

const artifactSha256 = sha256Hex("NEXINUS_ADMIT_PROOF_NOT_A_NODE");
const request = signedRequest("ADMIT", {
  nodeId: "ADMIT-PROOF",
  canonicalUrl: "https://admit-proof.invalid",
  artifactSha256,
});
const first = await post(request);
const replay = await post(request);
const duplicate = await post(signedRequest("ADMIT", {
  nodeId: "ADMIT-PROOF",
  canonicalUrl: "https://admit-proof-again.invalid",
  artifactSha256,
}));
const canonical = await post(signedRequest("ADMIT", {
  nodeId: "ARCHANGEL",
  canonicalUrl: "https://not-archangel.invalid",
  artifactSha256,
}));
const result = { documentValid, endpoint, first, replay, duplicate, canonical };
console.log(JSON.stringify(result, null, 2));
if (!first.valid || first.decision !== "ACCEPTED" || first.reason !== "SIGNED_ADMIT") process.exit(1);
if (!replay.valid || replay.status !== 409 || replay.reason !== "REPLAY") process.exit(1);
if (!duplicate.valid || duplicate.reason !== "ALREADY_ADMITTED") process.exit(1);
if (!canonical.valid || canonical.reason !== "CANONICAL_NODE") process.exit(1);
