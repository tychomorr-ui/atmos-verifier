#!/usr/bin/env node
import { createPublicKey, verify } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { canonicalJson, publicKeyFingerprint, sha256Hex, verifySignedManifest } from "./atmos-canonical.mjs";

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

const fileNode = (nodeId) => nodeId.toLowerCase();
const errorText = (error) => error instanceof Error ? error.message : String(error);

function fingerprintFromDocument(document) {
  if (!document || typeof document !== "object") return null;
  if (typeof document.identity?.publicKeyPem === "string") return publicKeyFingerprint(document.identity.publicKeyPem);
  if (typeof document.publicKeyPem === "string") return publicKeyFingerprint(document.publicKeyPem);
  if (typeof document.publicKey === "string") {
    const raw = Buffer.from(document.publicKey, "base64");
    if (raw.length === 44) return sha256Hex(raw);
  }
  return null;
}

async function fetchOnce(url) {
  const startedAt = new Date().toISOString();
  try {
    const response = await fetch(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(10000) });
    const body = await response.text();
    let parsed = null;
    try { parsed = JSON.parse(body); } catch { parsed = null; }
    return {
      outcome: "RESPONDED",
      statusCode: response.status,
      location: response.headers.get("location"),
      contentType: response.headers.get("content-type"),
      bodySha256: sha256Hex(body),
      parsed,
      startedAt,
      completedAt: new Date().toISOString(),
    };
  } catch (error) {
    return {
      outcome: error?.name === "TimeoutError" ? "TIMEOUT" : "NETWORK_ERROR",
      statusCode: null,
      location: null,
      contentType: null,
      bodySha256: null,
      parsed: null,
      error: errorText(error),
      startedAt,
      completedAt: new Date().toISOString(),
    };
  }
}

function healthMatches(health, manifest, fingerprint) {
  if (!health || health.schema !== "NEXINUS_ATMOS_SIGNED_HEALTH/v1" || health.status !== "ok") return false;
  if (health.manifestCid !== `sha256:${manifest.payloadHash}`) return false;
  if (!health.serviceSignature || !health.codeHash?.startsWith("sha256:")) return false;
  const { serviceSignature, ...payload } = health;
  try {
    return verify(null, Buffer.from(canonicalJson(payload)), createPublicKey(manifest.identity.publicKeyPem), Buffer.from(serviceSignature, "base64"))
      && fingerprint === manifest.identity.identityHash;
  } catch {
    return false;
  }
}

const results = [];
for (const node of declarations.nodes) {
  const slug = fileNode(node.nodeId);
  const manifest = JSON.parse(await readFile(resolve(manifestDir, `${slug}.signed.json`), "utf8"));
  const expectedNode = expected.nodes[node.nodeId];
  const local = verifySignedManifest(manifest, expectedNode.publicKeyFingerprintSha256);
  const endpoint = new URL(node.declaredCanonicalUrl);
  if (endpoint.protocol !== "https:") throw new Error(`${node.nodeId} endpoint is not HTTPS`);
  let identityProbe = null;
  let healthProbe = null;
  if (allowNetwork) {
    identityProbe = await fetchOnce(new URL("/.well-known/atmos-identity.json", endpoint).toString());
    healthProbe = await fetchOnce(new URL("/health", endpoint).toString());
  }
  const servedFingerprint = fingerprintFromDocument(identityProbe?.parsed);
  const identityMatched = servedFingerprint === local.publicKeyFingerprintSha256;
  const servedManifestMatched = identityProbe?.parsed?.payloadHash === manifest.payloadHash;
  const healthMatched = healthMatches(healthProbe?.parsed, manifest, local.publicKeyFingerprintSha256);
  const artifactMatched = expectedNode.artifactSha256 !== null && healthProbe?.parsed?.codeHash === `sha256:${expectedNode.artifactSha256}`;
  let status = "LOCAL_SIGNED_REMOTE_UNVERIFIED";
  if (!local.valid) status = "LOCAL_SIGNATURE_INVALID";
  else if (!allowNetwork) status = "LOCAL_SIGNED_REMOTE_UNVERIFIED";
  else if (identityProbe?.outcome !== "RESPONDED" || identityProbe.statusCode == null) status = "PROBE_FAILED";
  else if (identityProbe.statusCode !== 200 || !servedFingerprint) status = "REMOTE_IDENTITY_NOT_PUBLISHED";
  else if (!identityMatched) status = "REMOTE_IDENTITY_MISMATCH";
  else if (!servedManifestMatched) status = "REMOTE_KEY_MATCH_MANIFEST_NOT_SERVED";
  else if (!healthMatched || !artifactMatched) status = "REMOTE_IDENTITY_MATCH_ARTIFACT_UNBOUND";
  else status = "VERIFIED";
  const receipt = {
    schema: "NEXINUS_ATMOS_SIGNED_HEALTH_OBSERVATION/v1",
    nodeId: node.nodeId,
    displayName: node.displayName,
    targetUrl: endpoint.toString(),
    authorization: allowNetwork ? { operatorInitiated: true, authorizationReference, authorizedBy, allowNetwork: true } : { operatorInitiated: false, allowNetwork: false },
    local,
    identityProbe: identityProbe && { outcome: identityProbe.outcome, statusCode: identityProbe.statusCode, location: identityProbe.location, contentType: identityProbe.contentType, bodySha256: identityProbe.bodySha256, servedFingerprint, servedManifestMatched, error: identityProbe.error ?? null },
    healthProbe: healthProbe && { outcome: healthProbe.outcome, statusCode: healthProbe.statusCode, location: healthProbe.location, bodySha256: healthProbe.bodySha256, schema: healthProbe.parsed?.schema ?? null, error: healthProbe.error ?? null },
    status,
    boundary: "VERIFIED requires the served public-key fingerprint, signed manifest hash, and artifact hash to match. HTTP 2xx is not sufficient.",
  };
  await writeFile(resolve(receiptDir, `${slug}.observation.json`), `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  results.push({ nodeId: node.nodeId, displayName: node.displayName, endpoint: endpoint.toString(), status, publicKeyFingerprintSha256: local.publicKeyFingerprintSha256 });
  console.log(JSON.stringify(results.at(-1)));
}

const report = {
  schema: "NEXINUS_ATMOS_CANONICAL_VERIFICATION_REPORT/v1",
  generatedAt: new Date().toISOString(),
  authorizationReference: allowNetwork ? authorizationReference : null,
  authorizedBy: allowNetwork ? authorizedBy : null,
  networkProbe: allowNetwork,
  policy: { synchronizedRequires: "served-fingerprint-and-signed-health-and-artifact-hash", headAloneIsNotSynchronized: true },
  results,
  counts: {
    verified: results.filter((item) => item.status === "VERIFIED").length,
    localSignedRemoteUnverified: results.filter((item) => item.status === "LOCAL_SIGNED_REMOTE_UNVERIFIED").length,
    remoteIdentityMismatch: results.filter((item) => item.status === "REMOTE_IDENTITY_MISMATCH").length,
    remoteIdentityNotPublished: results.filter((item) => item.status === "REMOTE_IDENTITY_NOT_PUBLISHED").length,
    remoteKeyMatchManifestNotServed: results.filter((item) => item.status === "REMOTE_KEY_MATCH_MANIFEST_NOT_SERVED").length,
    identityMatchArtifactUnbound: results.filter((item) => item.status === "REMOTE_IDENTITY_MATCH_ARTIFACT_UNBOUND").length,
    probeFailed: results.filter((item) => item.status === "PROBE_FAILED").length,
    localInvalid: results.filter((item) => item.status === "LOCAL_SIGNATURE_INVALID").length,
  },
};
await writeFile(resolve(root, "atmos-sync-report.json"), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify(report.counts));
