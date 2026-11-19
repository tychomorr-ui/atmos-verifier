import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { canonicalJson, publicKeyFingerprint, sha256Hex, verifySignedManifest } from "../atmos-canonical.mjs";
import { selectHealthProbe } from "../atmos-health-paths.mjs";
import { quantusCanonicalPayload, verifyQuantusStatus } from "../quantus-status.mjs";
import { verifyQuantusWitnessStatus } from "../quantus-witness-adapter.mjs";
import { CANONICAL_NODE_IDS, isCanonicalNodeId } from "../atmos-governance-identities.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const now = 1700000000;
const fresh = { nowSeconds: now };
const digest = text => createHash("sha256").update(text).digest("hex");

// The exact producer algorithms from Quantus: Python sort_keys, compact JSON,
// ensure_ascii=False for signing and its default ensure_ascii=True on the wire.
// Python makes the payload; Node signs the Python-produced canonical bytes with
// an ephemeral key. There are no persisted private keys or production pins.
function fixture(observedAt = now) {
  const py = String.raw`
import json
p={"schema":"QUANTUS_WITNESS_STATUS/v1","nodeId":"QUANTUS","service":"QUANTUS_WITNESS_CONSOLE","status":"READY","observedAt":1700000000,"checks":{"remoteChecksPerformed":False,"egressPolicy":"NO_REMOTE_PROBES"},"host":{"uptimeSeconds":420448.0,"small":1e-07,"zero":-0.0,"hostname":"café"},"capabilities":["SIGN_STATUS"],"reviewBoundary":"OBSERVATION_ONLY_NOT_A_LEGAL_EFFECT_DETERMINATION","unicode":{"\ue000":"bmp","\U00010000":"astral"}}
print(json.dumps({"wire":json.dumps(p,sort_keys=True,separators=(',',':')),"canonical":json.dumps(p,sort_keys=True,separators=(',',':'),ensure_ascii=False)}))
`.replace("1700000000", String(observedAt));
  const result = spawnSync("python3", ["-c", py], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const { wire, canonical } = JSON.parse(result.stdout);
  const keys = generateKeyPairSync("ed25519");
  const key = keys.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  const sig = sign(null, Buffer.from(canonical), keys.privateKey).toString("base64");
  const raw = `${wire.slice(0, -1)},"payloadHash":"sha256:${digest(canonical)}","publicKey":"${key}","signatureAlgorithm":"Ed25519","signature":"${sig}"}`;
  return { raw, canonical, key, keys };
}

function rehash(raw) {
  return raw.replace(/"payloadHash":"sha256:[a-f0-9]{64}"/, `"payloadHash":"sha256:${digest(quantusCanonicalPayload(raw))}"`);
}
function resign(raw, privateKey) {
  raw = rehash(raw);
  const signature = sign(null, Buffer.from(quantusCanonicalPayload(raw)), privateKey).toString("base64");
  return raw.replace(/"signature":"[A-Za-z0-9+/=]+"/, `"signature":"${signature}"`);
}
function tempDir() { return mkdtempSync(join(root, "tests", ".tmp-")); }
function writeJson(path, value) { writeFileSync(path, JSON.stringify(value)); }
function runSync(dir, env = {}) {
  return spawnSync(process.execPath, [join(root, "atmos-sync-all.mjs")], {
    cwd: dir, encoding: "utf8", env: { ...process.env, ATMOS_ALLOW_NETWORK: "0", ATMOS_AUTHORIZED_BY: "", ATMOS_QUANTUS_PINNED_PUBLIC_KEY: "", ...env },
  });
}

test("Python canonical wire interoperates, including floats, exponent, Unicode, and codepoint key order", () => {
  const f = fixture();
  assert.match(f.raw, /420448\.0/);
  assert.match(f.raw, /-0\.0/);
  assert.match(f.raw, /1e-07/);
  assert.equal(quantusCanonicalPayload(f.raw), f.canonical);
  assert.deepEqual(verifyQuantusStatus(f.raw, f.key, fresh), { valid: true, reason: null, observedAt: now, reportedStatus: "READY", payloadHash: `sha256:${digest(f.canonical)}` });
});

test("missing or wrong operator key, signed-content tampering, and envelope tampering are untrusted", () => {
  const f = fixture(), other = fixture();
  assert.equal(verifyQuantusStatus(f.raw, undefined, fresh).reason, "PIN_NOT_CONFIGURED");
  assert.equal(verifyQuantusStatus(f.raw, "not-a-key", fresh).reason, "INVALID_PIN");
  assert.equal(verifyQuantusStatus(f.raw, other.key, fresh).reason, "PUBLIC_KEY_MISMATCH");
  const changed = f.raw.replace("420448.0", "420449.0");
  assert.equal(verifyQuantusStatus(changed, f.key, fresh).reason, "PAYLOAD_HASH_MISMATCH");
  assert.equal(verifyQuantusStatus(rehash(changed), f.key, fresh).reason, "INVALID_SIGNATURE");
  const badSignature = f.raw.replace(/("signature":")[A-Za-z0-9+/]/, '$1!');
  assert.equal(verifyQuantusStatus(badSignature, f.key, fresh).reason, "INVALID_SIGNATURE");
  const keySubstitution = f.raw.replace(f.key, other.key);
  assert.equal(verifyQuantusStatus(keySubstitution, f.key, fresh).reason, "PUBLIC_KEY_MISMATCH");
  const forgedKeyLabel = other.raw.replace(other.key, f.key);
  assert.equal(verifyQuantusStatus(forgedKeyLabel, f.key, fresh).reason, "INVALID_SIGNATURE");
  assert.equal(verifyQuantusStatus(f.raw.replace('"signatureAlgorithm":"Ed25519"', '"signatureAlgorithm":"RSA"'), f.key, fresh).reason, "UNEXPECTED_DOCUMENT");
  assert.equal(verifyQuantusStatus(f.raw.replace('{', '{"nodeId":"EVIL",'), f.key, fresh).reason, "DUPLICATE_JSON_KEY");
});

test("upstream fingerprint adapter requires raw bytes and an independent SPKI fingerprint", () => {
  const f = fixture();
  const fingerprint = sha256Hex(Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(f.key, "hex")]));
  assert.equal(verifyQuantusWitnessStatus(f.raw, fingerprint, fresh).valid, true);
  assert.equal(verifyQuantusWitnessStatus(JSON.parse(f.raw), fingerprint, fresh).reason, "RAW_BODY_REQUIRED");
  assert.equal(verifyQuantusWitnessStatus(f.raw, "0".repeat(64), fresh).reason, "PUBLIC_KEY_FINGERPRINT_MISMATCH");
  assert.equal(verifyQuantusWitnessStatus(f.raw, undefined, fresh).reason, "FINGERPRINT_NOT_CONFIGURED");
});

test("signed timestamps are bounded and wrong signed node, service or schema is rejected", () => {
  const f = fixture();
  assert.equal(verifyQuantusStatus(f.raw, f.key, { nowSeconds: now + 301 }).reason, "STALE");
  assert.equal(verifyQuantusStatus(f.raw, f.key, { nowSeconds: now - 31 }).reason, "FUTURE");
  assert.equal(verifyQuantusStatus(f.raw, f.key, { nowSeconds: now + 300 }).valid, true);
  assert.equal(verifyQuantusStatus(f.raw, f.key, { nowSeconds: now - 30 }).valid, true);
  assert.equal(verifyQuantusStatus(f.raw, f.key, { nowSeconds: now, maxAgeSeconds: 301 }).reason, "INVALID_TIME_POLICY");
  assert.equal(verifyQuantusStatus(f.raw, f.key, { nowSeconds: now, maxFutureSkewSeconds: 31 }).reason, "INVALID_TIME_POLICY");
  for (const [a, b] of [["QUANTUS_WITNESS_STATUS/v1", "WRONG_SCHEMA"], ['"nodeId":"QUANTUS"', '"nodeId":"OTHER"'], ["QUANTUS_WITNESS_CONSOLE", "OTHER_SERVICE"]]) {
    assert.equal(verifyQuantusStatus(resign(f.raw.replace(a, b), f.keys.privateKey), f.key, fresh).reason, "UNEXPECTED_DOCUMENT");
  }
  const degraded = resign(f.raw.replace('"status":"READY"', '"status":"DEGRADED"'), f.keys.privateKey);
  assert.equal(verifyQuantusStatus(degraded, f.key, fresh).reportedStatus, "DEGRADED");
});

test("configured health paths select deterministically and never fall back from an invalid 200", async () => {
  const called = [];
  const fetcher = async url => { called.push(new URL(url).pathname); return { outcome: "RESPONDED", statusCode: called.length === 1 ? 404 : 200, raw: "bad signature", parsed: {} }; };
  const result = await selectHealthProbe("https://example.test", ["/v1/health", "/.well-known/atmos-health.json", "/v1/status"], fetcher);
  assert.deepEqual(called, ["/v1/health", "/.well-known/atmos-health.json"]);
  assert.equal(result.selectedPath, "/.well-known/atmos-health.json");
  for (const statusCode of [200, 301, 403, 500]) {
    let count = 0;
    await selectHealthProbe("https://example.test", ["/v1/health", "/.well-known/atmos-health.json"], async () => { count++; return { outcome: "RESPONDED", statusCode }; });
    assert.equal(count, 1);
  }
  let count = 0;
  await selectHealthProbe("https://example.test", ["/v1/health", "/v1/status"], async () => { count++; return { outcome: "NETWORK_ERROR", statusCode: null }; });
  assert.equal(count, 1);
  await assert.rejects(selectHealthProbe("https://example.test", ["//evil.test/health"], fetcher));
  await assert.rejects(selectHealthProbe("https://example.test", ["/health", "/health"], fetcher));
});

test("existing signed manifests validate against both prior key and manifest pins", () => {
  const expected = JSON.parse(readFileSync(join(root, "expected-identity-hashes.json"), "utf8"));
  for (const [id, pin] of Object.entries(expected.nodes)) {
    if (id === "QUANTUS") continue; // Quantus has a status key, not a signed ATMOS manifest.
    const manifest = JSON.parse(readFileSync(join(root, "signed-manifests", `${id.toLowerCase()}.signed.json`), "utf8"));
    assert.equal(verifySignedManifest(manifest, pin.publicKeyFingerprintSha256, pin.manifestPayloadSha256).valid, true, id);
    assert.equal(verifySignedManifest(manifest, "0".repeat(64), pin.manifestPayloadSha256).valid, false, id);
    assert.equal(verifySignedManifest(manifest, pin.publicKeyFingerprintSha256, "0".repeat(64)).valid, false, id);
  }
});

test("offline default keeps all eleven legacy checks and does not issue network requests", () => {
  const dir = tempDir();
  try {
    cpSync(join(root, "signed-manifests"), join(dir, "signed-manifests"), { recursive: true });
    for (const name of ["node-declarations.json", "expected-identity-hashes.json"]) cpSync(join(root, name), join(dir, name));
    const routes = join(dir, "routes.json"), log = join(dir, "requests.log"); writeJson(routes, {});
    const result = runSync(dir, { NODE_OPTIONS: `--import=${pathToFileURL(join(root, "tests/mock-fetch.mjs"))}`, ATMOS_TEST_ROUTES: routes, ATMOS_TEST_LOG: log });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.counts.localSignedRemoteUnverified, 11);
    assert.equal(report.counts.localInvalid, 0);
    assert.equal(report.counts.witnessNotProbed, 1);
    assert.equal(report.counts.verified, 0);
    assert.throws(() => readFileSync(log), { code: "ENOENT" });
    const unauthorized = runSync(dir, { NODE_OPTIONS: `--import=${pathToFileURL(join(root, "tests/mock-fetch.mjs"))}`, ATMOS_TEST_ROUTES: routes, ATMOS_TEST_LOG: log, ATMOS_ALLOW_NETWORK: "1", ATMOS_AUTHORIZED_BY: "" });
    assert.notEqual(unauthorized.status, 0);
    assert.match(unauthorized.stderr, /Set ATMOS_AUTHORIZED_BY/);
    assert.throws(() => readFileSync(log), { code: "ENOENT" });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function integrationSetup(dir, f) {
  const keys = generateKeyPairSync("ed25519");
  const pem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = publicKeyFingerprint(pem), artifact = sha256Hex("integration artifact"), identityDocument = sha256Hex("identity document");
  const payload = { schema: "NEXINUS_ATMOS_SIGNED_NODE_MANIFEST/v1", nodeId: "TEST", declaredCanonicalUrl: "https://legacy.test", identity: { publicKeyPem: pem, identityHash: fingerprint }, hashes: { publicKeyFingerprintSha256: fingerprint, identityDocumentSha256: identityDocument, artifactSha256: artifact } };
  const manifest = { ...payload, payloadHash: sha256Hex(canonicalJson(payload)), signature: sign(null, Buffer.from(canonicalJson(payload)), keys.privateKey).toString("base64") };
  const healthPayload = { schema: "NEXINUS_ATMOS_SIGNED_HEALTH/v1", status: "ok", manifestCid: `sha256:${manifest.payloadHash}`, codeHash: `sha256:${artifact}` };
  const health = { ...healthPayload, serviceSignature: sign(null, Buffer.from(canonicalJson(healthPayload)), keys.privateKey).toString("base64") };
  cpSync(join(root, "signed-manifests"), join(dir, "signed-manifests"), { recursive: true });
  writeJson(join(dir, "signed-manifests/test.signed.json"), manifest);
  writeJson(join(dir, "expected-identity-hashes.json"), { nodes: { TEST: { publicKeyFingerprintSha256: fingerprint, identityDocumentSha256: identityDocument, manifestPayloadSha256: manifest.payloadHash, artifactSha256: artifact } } });
  writeJson(join(dir, "node-declarations.json"), { nodes: [
    { nodeId: "TEST", displayName: "Legacy", declaredCanonicalUrl: "https://legacy.test", healthPaths: ["/health", "/v1/health"] },
    { nodeId: "QUANTUS", displayName: "Witness", declaredCanonicalUrl: "https://quantus.test", adapter: "QUANTUS_WITNESS_STATUS/v1", healthPaths: ["/v1/health", "/v1/status", "/.well-known/atmos-health.json"], maxAgeSeconds: 300, maxFutureSkewSeconds: 30 },
  ] });
  const routes = {
    "https://legacy.test/.well-known/atmos-identity.json": { status: 200, body: JSON.stringify(manifest) },
    "https://legacy.test/health": { status: 404 },
    "https://legacy.test/v1/health": { status: 200, body: JSON.stringify(health) },
    "https://quantus.test/v1/health": { status: 404 },
    "https://quantus.test/v1/status": { status: 410 },
    "https://quantus.test/.well-known/atmos-health.json": { status: 200, body: f.raw },
  };
  return { routes, manifest };
}

test("end-to-end GET-only fallback preserves legacy VERIFIED and separates signed witness status", () => {
  const dir = tempDir(), f = fixture(Math.floor(Date.now() / 1000));
  try {
    const { routes, manifest } = integrationSetup(dir, f);
    const routeFile = join(dir, "routes.json"), log = join(dir, "requests.log"); writeJson(routeFile, routes);
    const env = { NODE_OPTIONS: `--import=${pathToFileURL(join(root, "tests/mock-fetch.mjs"))}`, ATMOS_TEST_ROUTES: routeFile, ATMOS_TEST_LOG: log, ATMOS_ALLOW_NETWORK: "1", ATMOS_AUTHORIZED_BY: "test", ATMOS_QUANTUS_PINNED_PUBLIC_KEY: f.key };
    const result = runSync(dir, env); assert.equal(result.status, 0, result.stderr);
    let report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[0].status, "VERIFIED");
    assert.equal(report.results[1].status, "WITNESS_STATUS_SIGNATURE_VALID_ARTIFACT_UNBOUND");
    assert.equal(report.results[0].freshness, "UNCHECKED");
    assert.equal(report.results[0].replayProtection, "NONE");
    assert.equal(report.policy.legacyHealthReplayProtection, "NONE");
    assert.equal(report.counts.verified, 1);
    assert.match(readFileSync(log, "utf8"), /GET https:\/\/quantus.test\/\.well-known\/atmos-health.json/);
    assert.ok(readFileSync(log, "utf8").trim().split("\n").every(line => line.startsWith("GET ")));
    assert.equal(JSON.parse(readFileSync(join(dir, "verification-receipts/quantus.observation.json"))).healthProbe.selectedPath, "/.well-known/atmos-health.json");
    // Copying a public key and expected hash into an unsigned document is not a served manifest.
    const identityUrl = "https://legacy.test/.well-known/atmos-identity.json";
    routes[identityUrl] = { status: 200, body: JSON.stringify({ identity: manifest.identity, payloadHash: manifest.payloadHash }) };
    writeJson(routeFile, routes);
    const forgedIdentity = runSync(dir, env); assert.equal(forgedIdentity.status, 0, forgedIdentity.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[0].status, "REMOTE_KEY_MATCH_MANIFEST_NOT_SERVED");
    // A signed manifest is bound to its original node and URL, not a new declaration.
    routes[identityUrl] = { status: 200, body: JSON.stringify({ ...manifest, declaredCanonicalUrl: "https://other.test" }) };
    writeJson(routeFile, routes);
    const alteredIdentity = runSync(dir, env); assert.equal(alteredIdentity.status, 0, alteredIdentity.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[0].status, "REMOTE_KEY_MATCH_MANIFEST_NOT_SERVED");
    routes[identityUrl] = { status: 200, body: JSON.stringify(manifest) };
    // Malformed health content rejects cleanly and does not stop later nodes.
    const healthUrl = "https://legacy.test/health";
    routes[healthUrl] = { status: 200, body: JSON.stringify({ schema: "NEXINUS_ATMOS_SIGNED_HEALTH/v1", status: "ok", manifestCid: `sha256:${manifest.payloadHash}`, codeHash: 42, serviceSignature: "bad" }) };
    writeJson(routeFile, routes);
    const malformed = runSync(dir, env); assert.equal(malformed.status, 0, malformed.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[0].status, "REMOTE_IDENTITY_MATCH_ARTIFACT_UNBOUND");
    assert.equal(report.results[1].status, "WITNESS_STATUS_SIGNATURE_VALID_ARTIFACT_UNBOUND");
    // A response larger than the streaming limit fails without trying another path.
    routes[healthUrl] = { status: 200, body: "x".repeat(1024 * 1024 + 1) };
    writeJson(routeFile, routes); writeFileSync(log, "");
    const oversized = runSync(dir, env); assert.equal(oversized.status, 0, oversized.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[0].status, "PROBE_FAILED");
    assert.equal(report.results[1].status, "WITNESS_STATUS_SIGNATURE_VALID_ARTIFACT_UNBOUND");
    assert.doesNotMatch(readFileSync(log, "utf8"), /legacy.test\/v1\/health/);
    assert.equal(JSON.parse(readFileSync(join(dir, "verification-receipts/test.observation.json"))).healthProbe.attempts[0].outcome, "RESPONSE_TOO_LARGE");
    routes[healthUrl] = { status: 404 };
    // A tampered 200 blocks fallback even if the second endpoint would be valid.
    routes["https://quantus.test/v1/health"] = { status: 200, body: f.raw.replace("420448.0", "420449.0") };
    routes["https://quantus.test/v1/status"] = { status: 200, body: f.raw };
    writeJson(routeFile, routes); writeFileSync(log, "");
    const second = runSync(dir, env); assert.equal(second.status, 0, second.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[1].status, "WITNESS_STATUS_UNTRUSTED");
    assert.doesNotMatch(readFileSync(log, "utf8"), /quantus.test\/v1\/status/);
    // A missing pin cannot trust even a valid signed response.
    routes["https://quantus.test/v1/health"] = { status: 200, body: f.raw }; writeJson(routeFile, routes);
    const third = runSync(dir, { ...env, ATMOS_QUANTUS_PINNED_PUBLIC_KEY: "" }); assert.equal(third.status, 0, third.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[1].status, "WITNESS_PIN_NOT_CONFIGURED");
    // An existing observation-derived key remains a candidate, not automatic trust.
    const pinPath = join(dir, "expected-identity-hashes.json"), pins = JSON.parse(readFileSync(pinPath));
    pins.nodes.QUANTUS = { publicKeyHex: f.key, publicKeyFingerprintSha256: sha256Hex(Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(f.key, "hex")])) };
    writeJson(pinPath, pins);
    const candidate = runSync(dir, { ...env, ATMOS_QUANTUS_PINNED_PUBLIC_KEY: "" }); assert.equal(candidate.status, 0, candidate.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[1].status, "WITNESS_CANDIDATE_SIGNATURE_VALID_PIN_UNCONFIRMED");
    assert.equal(report.counts.witnessCandidateSignatureValid, 1);
    assert.equal(report.counts.verified, 1); // Only the legacy binding is counted.
    assert.equal(JSON.parse(readFileSync(join(dir, "verification-receipts/quantus.observation.json"))).pinSource, "RECORDED_UNCONFIRMED");
    // The actual /v1/health path also verifies when independently pinned.
    const direct = runSync(dir, env); assert.equal(direct.status, 0, direct.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[1].status, "WITNESS_STATUS_SIGNATURE_VALID_ARTIFACT_UNBOUND");
    assert.equal(JSON.parse(readFileSync(join(dir, "verification-receipts/quantus.observation.json"))).healthProbe.selectedPath, "/v1/health");
    // A signed health body delivered with HTTP 500 cannot promote a legacy node.
    routes["https://legacy.test/health"] = { ...routes["https://legacy.test/v1/health"], status: 500 }; writeJson(routeFile, routes);
    const serverError = runSync(dir, env); assert.equal(serverError.status, 0, serverError.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[0].status, "REMOTE_IDENTITY_MATCH_ARTIFACT_UNBOUND");
    // A contradictory signed artifact claim cannot match a different artifact pin.
    routes["https://legacy.test/health"] = { status: 404 }; writeJson(routeFile, routes);
    const originalArtifact = pins.nodes.TEST.artifactSha256;
    pins.nodes.TEST.artifactSha256 = "0".repeat(64); writeJson(pinPath, pins);
    const unbound = runSync(dir, env); assert.equal(unbound.status, 0, unbound.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[0].status, "LOCAL_SIGNATURE_INVALID");
    pins.nodes.TEST.artifactSha256 = originalArtifact;
    const originalIdentity = pins.nodes.TEST.identityDocumentSha256;
    pins.nodes.TEST.identityDocumentSha256 = "0".repeat(64); writeJson(pinPath, pins);
    const wrongIdentityHash = runSync(dir, env); assert.equal(wrongIdentityHash.status, 0, wrongIdentityHash.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[0].status, "LOCAL_SIGNATURE_INVALID");
    pins.nodes.TEST.identityDocumentSha256 = originalIdentity;
    // A wrong independently pinned legacy manifest hash is never VERIFIED.
    pins.nodes.TEST.manifestPayloadSha256 = "0".repeat(64); writeJson(pinPath, pins);
    const fourth = runSync(dir, env); assert.equal(fourth.status, 0, fourth.stderr);
    report = JSON.parse(readFileSync(join(dir, "atmos-sync-report.json")));
    assert.equal(report.results[0].status, "LOCAL_SIGNATURE_INVALID");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("governance reservations include Quantus and the separate Core/Mirror IDs without enrolling them", () => {
  for (const id of ["QUANTUS", "TESSERACT-A-CORE", "TESSERACT-MIRROR", "TESSERACT-A", "TESSERACT-TERMINUS"]) {
    assert.ok(CANONICAL_NODE_IDS.has(id));
    assert.equal(isCanonicalNodeId(id), true);
  }
  assert.equal(isCanonicalNodeId("NEW-UNKNOWN-NODE"), false);
  assert.match(readFileSync(join(root, "atmos-governance-server.mjs"), "utf8"), /isCanonicalNodeId\(request\.nodeId\)/);
});
