import { createHash, createPublicKey, verify } from "node:crypto";

export function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sortValue(item)]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(sortValue(value));
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function publicKeyFingerprint(publicKeyPem) {
  return sha256Hex(createPublicKey(publicKeyPem).export({ format: "der", type: "spki" }));
}

export function unsignedPayload(manifest) {
  const { signature: _signature, payloadHash: _payloadHash, ...payload } = manifest;
  return payload;
}

export function verifySignedManifest(manifest, expectedFingerprint) {
  const fingerprint = publicKeyFingerprint(manifest.identity.publicKeyPem);
  const payload = canonicalJson(unsignedPayload(manifest));
  const payloadHash = sha256Hex(payload);
  const signatureValid = verify(null, Buffer.from(payload), createPublicKey(manifest.identity.publicKeyPem), Buffer.from(manifest.signature, "base64"));
  const fingerprintMatchesManifest = fingerprint === manifest.identity.identityHash && fingerprint === manifest.hashes?.publicKeyFingerprintSha256;
  const fingerprintMatchesExpected = !expectedFingerprint || fingerprint === expectedFingerprint;
  const payloadMatches = payloadHash === manifest.payloadHash;
  return {
    valid: signatureValid && fingerprintMatchesManifest && fingerprintMatchesExpected && payloadMatches,
    publicKeyFingerprintSha256: fingerprint,
    manifestPayloadSha256: payloadHash,
    signatureValid,
    payloadMatches,
    fingerprintMatchesManifest,
    fingerprintMatchesExpected,
  };
}
