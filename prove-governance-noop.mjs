#!/usr/bin/env node
import { generateKeyPairSync, sign, verify, createPublicKey } from "node:crypto";
import { canonicalJson } from "./atmos-canonical.mjs";

const endpoint = process.env.ATMOS_GOVERNANCE_URL || "https://archangel.nexinus.net/governance/noop";
const documentUrl = new URL("/.well-known/atmos-governance.json", endpoint).toString();
const governance = await (await fetch(documentUrl)).json();
const { signature: _signature, payloadHash: _payloadHash, ...unsigned } = governance;
const documentValid = verify(null, Buffer.from(canonicalJson(unsigned)), createPublicKey(governance.publicKeyPem), Buffer.from(governance.signature, "base64"));
if (!documentValid) throw new Error("Governance document signature is invalid");

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
const nonce = `public-noop-${Date.now()}-${Math.random().toString(16).slice(2)}`;
const payload = {
  schema: "NEXINUS_ATMOS_GOVERNANCE_REQUEST/v1",
  action: "NOOP",
  nonce,
  requestedAt: new Date().toISOString(),
  publicKeyPem,
};
const request = { ...payload, signature: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString("base64") };

async function post(body) {
  const response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const decision = await response.json();
  const { serviceSignature, ...decisionPayload } = decision;
  const valid = verify(null, Buffer.from(canonicalJson(decisionPayload)), createPublicKey(governance.publicKeyPem), Buffer.from(serviceSignature, "base64"));
  return { status: response.status, decision: decision.decision, reason: decision.reason, valid };
}

const first = await post(request);
const replay = await post(request);
console.log(JSON.stringify({ documentValid, endpoint, first, replay }, null, 2));
if (!first.valid || !replay.valid || first.decision !== "ACCEPTED" || replay.reason !== "REPLAY") process.exit(1);
