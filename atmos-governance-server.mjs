#!/usr/bin/env node
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { canonicalJson, publicKeyFingerprint, sha256Hex } from "./atmos-canonical.mjs";

const keyPath = process.env.ARCHANGEL_KEY_PATH;
const statePath = process.env.ARCHANGEL_STATE_PATH || "/var/lib/atmos-governance/seen.json";
const port = Number(process.env.ARCHANGEL_GOVERNANCE_PORT || 8787);
if (!keyPath) throw new Error("Set ARCHANGEL_KEY_PATH");

const privateKey = createPrivateKey(await readFile(keyPath));
const publicKeyPem = createPublicKey(privateKey).export({ format: "pem", type: "spki" }).toString();
const fingerprint = publicKeyFingerprint(publicKeyPem);

async function loadSeen() {
  try {
    return new Set(JSON.parse(await readFile(statePath, "utf8")).requestHashes ?? []);
  } catch (error) {
    if (error?.code === "ENOENT") return new Set();
    throw error;
  }
}

async function saveSeen(seen) {
  await mkdir(dirname(statePath), { recursive: true });
  await writeFile(statePath, `${JSON.stringify({ requestHashes: [...seen] }, null, 2)}\n`, { mode: 0o600 });
}

function decisionFor(requestHash, requesterFingerprint, nonce, decision, reason) {
  const payload = {
    schema: "NEXINUS_ATMOS_GOVERNANCE_DECISION/v1",
    nodeId: "ARCHANGEL",
    action: "NOOP",
    decision,
    reason,
    requestHash,
    requesterFingerprint,
    nonce,
    publicKeyFingerprintSha256: fingerprint,
    decidedAt: new Date().toISOString(),
    boundary: "A signed decision proves this control-plane key accepted or rejected the request hash. NOOP changes no node.",
  };
  return { ...payload, serviceSignature: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString("base64") };
}

function verifyRequest(request) {
  if (!request || request.schema !== "NEXINUS_ATMOS_GOVERNANCE_REQUEST/v1") return { ok: false, reason: "MALFORMED" };
  if (typeof request.nonce !== "string" || request.nonce.length < 16 || request.nonce.length > 128) return { ok: false, reason: "MALFORMED" };
  if (typeof request.publicKeyPem !== "string" || typeof request.signature !== "string") return { ok: false, reason: "MALFORMED" };
  const { signature, ...payload } = request;
  try {
    const valid = verify(null, Buffer.from(canonicalJson(payload)), createPublicKey(request.publicKeyPem), Buffer.from(signature, "base64"));
    if (!valid) return { ok: false, reason: "INVALID_SIGNATURE" };
  } catch {
    return { ok: false, reason: "INVALID_SIGNATURE" };
  }
  if (request.action !== "NOOP") return { ok: false, reason: "UNSUPPORTED_ACTION", requesterFingerprint: publicKeyFingerprint(request.publicKeyPem) };
  return { ok: true, requesterFingerprint: publicKeyFingerprint(request.publicKeyPem) };
}

const seen = await loadSeen();
const server = createServer(async (incoming, outgoing) => {
  if (incoming.method !== "POST" || incoming.url !== "/governance/noop") {
    outgoing.writeHead(404, { "content-type": "application/json" });
    outgoing.end(`${JSON.stringify({ error: "NOT_FOUND" })}\n`);
    return;
  }
  const chunks = [];
  for await (const chunk of incoming) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8");
  let request = null;
  try { request = JSON.parse(raw); } catch { request = null; }
  const checked = verifyRequest(request);
  const { signature: _signature, ...unsigned } = request ?? {};
  const requestHash = request ? sha256Hex(canonicalJson(unsigned)) : sha256Hex(raw);
  const nonce = request?.nonce ?? null;
  if (!checked.ok) {
    const body = decisionFor(requestHash, checked.requesterFingerprint ?? null, nonce, "REJECTED", checked.reason);
    outgoing.writeHead(400, { "content-type": "application/json" });
    outgoing.end(`${JSON.stringify(body, null, 2)}\n`);
    return;
  }
  if (seen.has(requestHash)) {
    const body = decisionFor(requestHash, checked.requesterFingerprint, nonce, "REJECTED", "REPLAY");
    outgoing.writeHead(409, { "content-type": "application/json" });
    outgoing.end(`${JSON.stringify(body, null, 2)}\n`);
    return;
  }
  seen.add(requestHash);
  await saveSeen(seen);
  const body = decisionFor(requestHash, checked.requesterFingerprint, nonce, "ACCEPTED", "SIGNED_NOOP");
  outgoing.writeHead(200, { "content-type": "application/json" });
  outgoing.end(`${JSON.stringify(body, null, 2)}\n`);
});

server.listen(port, "127.0.0.1", () => {
  console.log(`ARCHANGEL governance listening on 127.0.0.1:${port} fingerprint=${fingerprint}`);
});
