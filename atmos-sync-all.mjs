#!/usr/bin/env node
import { createPublicKey, verify } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { canonicalJson, publicKeyFingerprint, sha256Hex, verifySignedManifest } from "./atmos-canonical.mjs";
import { selectHealthProbe } from "./atmos-health-paths.mjs";
import { verifyQuantusStatus } from "./quantus-status.mjs";

const root = process.cwd();
const allowNetwork = process.env.ATMOS_ALLOW_NETWORK === "1";
const authorizedBy = process.env.ATMOS_AUTHORIZED_BY;
if (allowNetwork && !authorizedBy) throw new Error("Set ATMOS_AUTHORIZED_BY before a network probe");
const authorizationReference = process.env.ATMOS_AUTHORIZATION_REFERENCE || `AUTH-ATMOS-${new Date().toISOString().slice(0, 10).replaceAll("-", "")}-CANONICAL-VERIFY`;
const declarations = JSON.parse(await readFile(resolve(root, "node-declarations.json"), "utf8"));
const expected = JSON.parse(await readFile(resolve(root, "expected-identity-hashes.json"), "utf8"));
const manifestDir = resolve(root, "signed-manifests");
const receiptDir = resolve(root, "verification-receipts");
await mkdir(receiptDir, { recursive: true });

const fileNode = nodeId => nodeId.toLowerCase();
const errorText = error => error instanceof Error ? error.message : String(error);
const authorization = allowNetwork ? { operatorInitiated: true, authorizationReference, authorizedBy, allowNetwork: true } : { operatorInitiated: false, allowNetwork: false };
const legacyBoundary = "VERIFIED requires pinned identity, manifest, and artifact bindings. Legacy health freshness and replay are not checked. HTTP 2xx is not sufficient.";
const witnessBoundary = "A pinned, signed, fresh witness status is an observation, not authority or manifest/artifact binding; it is never VERIFIED.";
const MAX_RESPONSE_BYTES = 1024 * 1024;

function fingerprintFromDocument(document) {
  if (!document || typeof document !== "object") return null;
  try {
    if (typeof document.identity?.publicKeyPem === "string") return publicKeyFingerprint(document.identity.publicKeyPem);
    if (typeof document.publicKeyPem === "string") return publicKeyFingerprint(document.publicKeyPem);
    if (typeof document.publicKey === "string") {
      const raw = Buffer.from(document.publicKey, "base64");
      if (raw.length === 44) return sha256Hex(raw);
    }
  } catch { return null; }
  return null;
}

async function fetchOnce(url) {
  const startedAt = new Date().toISOString();
  try {
    const response = await fetch(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(10000) });
    const chunks = [];
    let total = 0;
    const reader = response.body?.getReader();
    if (reader) {
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > MAX_RESPONSE_BYTES) {
            await reader.cancel();
            throw Object.assign(new Error("Response exceeds the 1 MiB limit"), { code: "RESPONSE_TOO_LARGE" });
          }
          chunks.push(Buffer.from(value));
        }
      } finally { reader.releaseLock(); }
    }
    const raw = Buffer.concat(chunks).toString("utf8");
    let parsed = null;
    try { parsed = JSON.parse(raw); } catch { parsed = null; }
    return { outcome: "RESPONDED", statusCode: response.status, location: response.headers.get("location"), contentType: response.headers.get("content-type"), bodySha256: sha256Hex(raw), parsed, raw, startedAt, completedAt: new Date().toISOString() };
  } catch (error) {
    return { outcome: error?.code === "RESPONSE_TOO_LARGE" ? "RESPONSE_TOO_LARGE" : error?.name === "TimeoutError" ? "TIMEOUT" : "NETWORK_ERROR", statusCode: null, location: null, contentType: null, bodySha256: null, parsed: null, raw: null, error: errorText(error), startedAt, completedAt: new Date().toISOString() };
  }
}

function healthMatches(health, manifest, fingerprint) {
  if (!health || health.schema !== "NEXINUS_ATMOS_SIGNED_HEALTH/v1" || health.status !== "ok") return false;
  if (health.manifestCid !== `sha256:${manifest.payloadHash}`) return false;
  if (typeof health.serviceSignature !== "string" || typeof health.codeHash !== "string" || !health.codeHash.startsWith("sha256:")) return false;
  const { serviceSignature, ...payload } = health;
  try {
    return verify(null, Buffer.from(canonicalJson(payload)), createPublicKey(manifest.identity.publicKeyPem), Buffer.from(serviceSignature, "base64")) && fingerprint === manifest.identity.identityHash;
  } catch { return false; }
}

const results = [];
for (const node of declarations.nodes) {
  const slug = fileNode(node.nodeId);
  const endpoint = new URL(node.declaredCanonicalUrl);
  if (endpoint.protocol !== "https:") throw new Error(`${node.nodeId} endpoint is not HTTPS`);
  if (node.adapter === "QUANTUS_WITNESS_STATUS/v1") {
    if (node.nodeId !== "QUANTUS") throw new Error("Quantus adapter requires nodeId QUANTUS");
    const operatorPin = process.env.ATMOS_QUANTUS_PINNED_PUBLIC_KEY;
    const recorded = expected.nodes.QUANTUS;
    const candidateKey = recorded?.publicKeyHex;
    const candidateValid = typeof candidateKey === "string" && /^[0-9a-f]{64}$/i.test(candidateKey)
      && sha256Hex(Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(candidateKey, "hex")])) === recorded.publicKeyFingerprintSha256;
    const pin = operatorPin || (candidateValid ? candidateKey : undefined);
    const pinSource = operatorPin ? "OPERATOR_SUPPLIED" : candidateValid ? "RECORDED_UNCONFIRMED" : "NONE";
    const health = allowNetwork ? await selectHealthProbe(endpoint, node.healthPaths, fetchOnce) : null;
    const p = health?.probe;
    const checked = p?.outcome === "RESPONDED" && p.statusCode === 200
      ? verifyQuantusStatus(p.raw, pin, { maxAgeSeconds: node.maxAgeSeconds, maxFutureSkewSeconds: node.maxFutureSkewSeconds }) : null;
    let status = "WITNESS_NOT_PROBED";
    if (allowNetwork && p?.outcome !== "RESPONDED") status = "PROBE_FAILED";
    else if (allowNetwork && p?.statusCode !== 200) status = "WITNESS_STATUS_NOT_PUBLISHED";
    else if (checked?.reason === "PIN_NOT_CONFIGURED") status = "WITNESS_PIN_NOT_CONFIGURED";
    else if (checked?.reason === "INVALID_PIN") status = "WITNESS_PIN_INVALID";
    else if (checked?.valid && pinSource === "RECORDED_UNCONFIRMED") status = "WITNESS_CANDIDATE_SIGNATURE_VALID_PIN_UNCONFIRMED";
    else if (checked?.valid) status = "WITNESS_STATUS_SIGNATURE_VALID_ARTIFACT_UNBOUND";
    else if (allowNetwork) status = "WITNESS_STATUS_UNTRUSTED";
    const receipt = {
      schema: "NEXINUS_ATMOS_WITNESS_STATUS_OBSERVATION/v1", nodeId: node.nodeId, displayName: node.displayName,
      targetUrl: endpoint.toString(), authorization, pinConfigured: Boolean(operatorPin), pinSource,
      healthProbe: health && { selectedPath: health.selectedPath, attempts: health.attempts, schema: p.parsed?.schema ?? null },
      witnessVerification: checked, status, boundary: witnessBoundary,
    };
    await writeFile(resolve(receiptDir, `${slug}.observation.json`), `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
    results.push({ nodeId: node.nodeId, displayName: node.displayName, endpoint: endpoint.toString(), status, reportedStatus: checked?.valid ? checked.reportedStatus : null });
    console.log(JSON.stringify(results.at(-1)));
    continue;
  }
  if (node.adapter) throw new Error(`Unknown adapter for ${node.nodeId}`);
  const manifest = JSON.parse(await readFile(resolve(manifestDir, `${slug}.signed.json`), "utf8"));
  const expectedNode = expected.nodes[node.nodeId];
  if (!expectedNode || !/^[0-9a-f]{64}$/.test(expectedNode.publicKeyFingerprintSha256 ?? "") || !/^[0-9a-f]{64}$/.test(expectedNode.manifestPayloadSha256 ?? "")) throw new Error(`Missing expected identity or manifest pin for ${node.nodeId}`);
  const local = verifySignedManifest(manifest, expectedNode.publicKeyFingerprintSha256, expectedNode.manifestPayloadSha256);
  local.nodeBindingMatches = manifest.schema === "NEXINUS_ATMOS_SIGNED_NODE_MANIFEST/v1" && manifest.nodeId === node.nodeId && manifest.declaredCanonicalUrl === node.declaredCanonicalUrl;
  local.signedClaimsMatchPins = /^[0-9a-f]{64}$/.test(expectedNode.identityDocumentSha256 ?? "")
    && manifest.hashes?.identityDocumentSha256 === expectedNode.identityDocumentSha256
    && Object.hasOwn(expectedNode, "artifactSha256")
    && manifest.hashes?.artifactSha256 === expectedNode.artifactSha256;
  local.valid = local.valid && local.nodeBindingMatches && local.signedClaimsMatchPins;
  let identityProbe = null, health = null;
  if (allowNetwork) {
    identityProbe = await fetchOnce(new URL("/.well-known/atmos-identity.json", endpoint).toString());
    health = await selectHealthProbe(endpoint, node.healthPaths ?? ["/health", "/v1/health", "/.well-known/atmos-health.json"], fetchOnce);
  }
  const healthProbe = health?.probe;
  const servedFingerprint = fingerprintFromDocument(identityProbe?.parsed);
  const identityMatched = servedFingerprint === local.publicKeyFingerprintSha256;
  let servedManifestMatched = false;
  try {
    const served = identityProbe?.parsed;
    servedManifestMatched = served?.schema === "NEXINUS_ATMOS_SIGNED_NODE_MANIFEST/v1"
      && served.nodeId === node.nodeId && served.declaredCanonicalUrl === node.declaredCanonicalUrl
      && verifySignedManifest(served, expectedNode.publicKeyFingerprintSha256, expectedNode.manifestPayloadSha256).valid;
  } catch { /* Missing or malformed served manifests remain unverified. */ }
  const healthMatched = healthProbe?.statusCode === 200 && healthMatches(healthProbe.parsed, manifest, local.publicKeyFingerprintSha256);
  const artifactMatched = /^[0-9a-f]{64}$/.test(expectedNode.artifactSha256 ?? "") && healthProbe?.parsed?.codeHash === `sha256:${expectedNode.artifactSha256}`;
  let status = "LOCAL_SIGNED_REMOTE_UNVERIFIED";
  if (!local.valid) status = "LOCAL_SIGNATURE_INVALID";
  else if (!allowNetwork) status = "LOCAL_SIGNED_REMOTE_UNVERIFIED";
  else if (identityProbe?.outcome !== "RESPONDED" || identityProbe.statusCode == null) status = "PROBE_FAILED";
  else if (identityProbe.statusCode !== 200 || !servedFingerprint) status = "REMOTE_IDENTITY_NOT_PUBLISHED";
  else if (!identityMatched) status = "REMOTE_IDENTITY_MISMATCH";
  else if (!servedManifestMatched) status = "REMOTE_KEY_MATCH_MANIFEST_NOT_SERVED";
  else if (healthProbe?.outcome !== "RESPONDED") status = "PROBE_FAILED";
  else if (!healthMatched || !artifactMatched) status = "REMOTE_IDENTITY_MATCH_ARTIFACT_UNBOUND";
  else status = "VERIFIED";
  const receipt = {
    schema: "NEXINUS_ATMOS_SIGNED_HEALTH_OBSERVATION/v1", nodeId: node.nodeId, displayName: node.displayName, targetUrl: endpoint.toString(), authorization, local,
    identityMapping: node.identityMapping ?? null,
    identityProbe: identityProbe && { outcome: identityProbe.outcome, statusCode: identityProbe.statusCode, location: identityProbe.location, contentType: identityProbe.contentType, bodySha256: identityProbe.bodySha256, servedFingerprint, servedManifestMatched, error: identityProbe.error ?? null },
    healthProbe: health && { selectedPath: health.selectedPath, attempts: health.attempts, schema: healthProbe.parsed?.schema ?? null },
    status, freshness: "UNCHECKED", replayProtection: "NONE", boundary: legacyBoundary,
  };
  await writeFile(resolve(receiptDir, `${slug}.observation.json`), `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  results.push({ nodeId: node.nodeId, displayName: node.displayName, endpoint: endpoint.toString(), status, publicKeyFingerprintSha256: local.publicKeyFingerprintSha256, identityMapping: node.identityMapping ?? null, freshness: "UNCHECKED", replayProtection: "NONE" });
  console.log(JSON.stringify(results.at(-1)));
}

const report = {
  schema: "NEXINUS_ATMOS_CANONICAL_VERIFICATION_REPORT/v1", generatedAt: new Date().toISOString(),
  authorizationReference: allowNetwork ? authorizationReference : null, authorizedBy: allowNetwork ? authorizedBy : null, networkProbe: allowNetwork,
  policy: { synchronizedRequires: "served-fingerprint-and-pinned-signed-manifest-and-signed-health-and-artifact-hash", legacyHealthFreshness: "UNCHECKED", legacyHealthReplayProtection: "NONE", headAloneIsNotSynchronized: true, witnessStatusIsNotVerified: true },
  results,
  counts: {
    verified: results.filter(item => item.status === "VERIFIED").length,
    localSignedRemoteUnverified: results.filter(item => item.status === "LOCAL_SIGNED_REMOTE_UNVERIFIED").length,
    remoteIdentityMismatch: results.filter(item => item.status === "REMOTE_IDENTITY_MISMATCH").length,
    remoteIdentityNotPublished: results.filter(item => item.status === "REMOTE_IDENTITY_NOT_PUBLISHED").length,
    remoteKeyMatchManifestNotServed: results.filter(item => item.status === "REMOTE_KEY_MATCH_MANIFEST_NOT_SERVED").length,
    identityMatchArtifactUnbound: results.filter(item => item.status === "REMOTE_IDENTITY_MATCH_ARTIFACT_UNBOUND").length,
    probeFailed: results.filter(item => item.status === "PROBE_FAILED").length,
    localInvalid: results.filter(item => item.status === "LOCAL_SIGNATURE_INVALID").length,
    witnessNotProbed: results.filter(item => item.status === "WITNESS_NOT_PROBED").length,
    witnessStatusSignatureValidArtifactUnbound: results.filter(item => item.status === "WITNESS_STATUS_SIGNATURE_VALID_ARTIFACT_UNBOUND").length,
    witnessCandidateSignatureValid: results.filter(item => item.status === "WITNESS_CANDIDATE_SIGNATURE_VALID_PIN_UNCONFIRMED").length,
    witnessUntrusted: results.filter(item => ["WITNESS_CANDIDATE_SIGNATURE_VALID_PIN_UNCONFIRMED", "WITNESS_PIN_NOT_CONFIGURED", "WITNESS_PIN_INVALID", "WITNESS_STATUS_UNTRUSTED", "WITNESS_STATUS_NOT_PUBLISHED"].includes(item.status)).length,
  },
};
await writeFile(resolve(root, "atmos-sync-report.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify(report.counts));
