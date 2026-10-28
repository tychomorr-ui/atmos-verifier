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

const CANONICAL_NODE_IDS = new Set([
  "ROOT-GATE", "TESSERACT-TERMINUS", "XINUS-CLARITY", "MONARCH-OS", "TESSERACT-A",
  "KEIRA", "VALKYRIE", "ARCHANGEL", "PROJECT-RECLAIM", "IWA-SAGE", "RESONATE-EARTH",
]);

const privateKey = createPrivateKey(await readFile(keyPath));
const publicKeyPem = createPublicKey(privateKey).export({ format: "pem", type: "spki" }).toString();
const fingerprint = publicKeyFingerprint(publicKeyPem);

async function loadState() {
  try {
    const parsed = JSON.parse(await readFile(statePath, "utf8"));
    return {
      requestHashes: new Set(parsed.requestHashes ?? []),
      admissions: Array.isArray(parsed.admissions) ? parsed.admissions : [],
    };
  } catch (error) {
    if (error?.code === "ENOENT") return { requestHashes: new Set(), admissions: [] };
    throw error;
  }
}

async function saveState(state) {
  await mkdir(dirname(statePath), { recursive: true });
  await writeFile(statePath, `${JSON.stringify({ requestHashes: [...state.requestHashes], admissions: state.admissions }, null, 2)}\n`, { mode: 0o600 });
}

function decisionFor(action, requestHash, requesterFingerprint, nonce, decision, reason) {
  const payload = {
    schema: "NEXINUS_ATMOS_GOVERNANCE_DECISION/v1",
    nodeId: "ARCHANGEL",
    action,
    decision,
    reason,
    requestHash,
    requesterFingerprint,
    nonce,
    publicKeyFingerprintSha256: fingerprint,
    decidedAt: new Date().toISOString(),
    boundary: action === "ADMIT"
      ? "A signed ADMIT decision records this request hash. It does not publish DNS, rotate a key, or mark a node VERIFIED."
      : "A signed decision proves this control-plane key accepted or rejected the request hash. NOOP changes no node.",
  };
  return { ...payload, serviceSignature: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString("base64") };
}

function verifyRequest(request, expectedAction) {
  if (!request || request.schema !== "NEXINUS_ATMOS_GOVERNANCE_REQUEST/v1") return { ok: false, reason: "MALFORMED" };
  if (typeof request.nonce !== "string" || request.nonce.length < 16 || request.nonce.length > 128) return { ok: false, reason: "MALFORMED" };
  if (typeof request.publicKeyPem !== "string" || typeof request.signature !== "string") return { ok: false, reason: "MALFORMED" };
  if (request.action !== expectedAction) return { ok: false, reason: "ACTION_PATH_MISMATCH" };
  const { signature, ...payload } = request;
  let requesterFingerprint = null;
  try {
    requesterFingerprint = publicKeyFingerprint(request.publicKeyPem);
    const valid = verify(null, Buffer.from(canonicalJson(payload)), createPublicKey(request.publicKeyPem), Buffer.from(signature, "base64"));
    if (!valid) return { ok: false, reason: "INVALID_SIGNATURE" };
  } catch {
    return { ok: false, reason: "INVALID_SIGNATURE" };
  }
  if (expectedAction === "ADMIT") {
    if (!/^[A-Z][A-Z0-9-]{2,63}$/.test(request.nodeId ?? "")) return { ok: false, reason: "MALFORMED", requesterFingerprint };
    if (!/^https:\/\/[a-z0-9.-]+(?::[0-9]{1,5})?$/.test(request.canonicalUrl ?? "")) return { ok: false, reason: "MALFORMED", requesterFingerprint };
    if (!/^[0-9a-f]{64}$/.test(request.artifactSha256 ?? "")) return { ok: false, reason: "MALFORMED", requesterFingerprint };
  }
  return { ok: true, requesterFingerprint };
}

function send(outgoing, status, body) {
  outgoing.writeHead(status, { "content-type": "application/json" });
  outgoing.end(`${JSON.stringify(body, null, 2)}\n`);
}

const state = await loadState();
const server = createServer(async (incoming, outgoing) => {
  const action = incoming.url === "/governance/noop" ? "NOOP" : incoming.url === "/governance/admit" ? "ADMIT" : null;
  if (incoming.method !== "POST" || !action) {
    send(outgoing, 404, { error: "NOT_FOUND" });
    return;
  }
  const chunks = [];
  for await (const chunk of incoming) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8");
  let request = null;
  try { request = JSON.parse(raw); } catch { request = null; }
  const checked = verifyRequest(request, action);
  const { signature: _signature, ...unsigned } = request ?? {};
  const requestHash = request ? sha256Hex(canonicalJson(unsigned)) : sha256Hex(raw);
  const nonce = request?.nonce ?? null;
  if (!checked.ok) {
    send(outgoing, 400, decisionFor(action, requestHash, checked.requesterFingerprint ?? null, nonce, "REJECTED", checked.reason));
    return;
  }
  if (state.requestHashes.has(requestHash)) {
    send(outgoing, 409, decisionFor(action, requestHash, checked.requesterFingerprint, nonce, "REJECTED", "REPLAY"));
    return;
  }
  if (action === "ADMIT") {
    if (CANONICAL_NODE_IDS.has(request.nodeId)) {
      send(outgoing, 409, decisionFor(action, requestHash, checked.requesterFingerprint, nonce, "REJECTED", "CANONICAL_NODE"));
      return;
    }
    if (state.admissions.some((item) => item.nodeId === request.nodeId || item.canonicalUrl === request.canonicalUrl)) {
      send(outgoing, 409, decisionFor(action, requestHash, checked.requesterFingerprint, nonce, "REJECTED", "ALREADY_ADMITTED"));
      return;
    }
    state.admissions.push({
      nodeId: request.nodeId,
      canonicalUrl: request.canonicalUrl,
      requesterFingerprint: checked.requesterFingerprint,
      artifactSha256: request.artifactSha256,
      requestHash,
      admittedAt: new Date().toISOString(),
    });
  }
  state.requestHashes.add(requestHash);
  await saveState(state);
  send(outgoing, 200, decisionFor(action, requestHash, checked.requesterFingerprint, nonce, "ACCEPTED", action === "ADMIT" ? "SIGNED_ADMIT" : "SIGNED_NOOP"));
});

server.listen(port, "127.0.0.1", () => {
  console.log(`ARCHANGEL governance listening on 127.0.0.1:${port} fingerprint=${fingerprint}`);
});
