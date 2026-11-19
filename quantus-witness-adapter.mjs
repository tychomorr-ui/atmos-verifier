import { createPublicKey, verify } from "node:crypto";
import { canonicalJson, sha256Hex } from "./atmos-canonical.mjs";

export const QUANTUS_WITNESS_SCHEMA = "QUANTUS_WITNESS_STATUS/v1";
export const QUANTUS_SIGNED_FIELDS = [
  "capabilities",
  "checks",
  "host",
  "nodeId",
  "observedAt",
  "reviewBoundary",
  "schema",
  "service",
  "status",
];

export function verifyQuantusWitnessStatus(document, expectedFingerprint) {
  if (!document || document.schema !== QUANTUS_WITNESS_SCHEMA) return { valid: false, reason: "SCHEMA_MISMATCH" };
  if (document.service !== "QUANTUS_WITNESS_CONSOLE" || document.nodeId !== "QUANTUS") return { valid: false, reason: "IDENTITY_MISMATCH" };
  if (document.status !== "READY" || document.signatureAlgorithm !== "Ed25519") return { valid: false, reason: "STATUS_OR_ALGORITHM_INVALID" };
  if (document.reviewBoundary !== "OBSERVATION_ONLY_NOT_A_LEGAL_EFFECT_DETERMINATION") return { valid: false, reason: "REVIEW_BOUNDARY_MISSING" };
  if (typeof document.publicKey !== "string" || !/^[0-9a-f]{64}$/i.test(document.publicKey)) return { valid: false, reason: "PUBLIC_KEY_INVALID" };
  if (typeof document.signature !== "string" || typeof document.payloadHash !== "string") return { valid: false, reason: "SIGNED_FIELDS_MISSING" };
  const payload = Object.fromEntries(QUANTUS_SIGNED_FIELDS.map((key) => [key, document[key]]));
  const canonical = Buffer.from(canonicalJson(payload));
  const fingerprint = sha256Hex(Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(document.publicKey, "hex")]));
  if (fingerprint !== expectedFingerprint) return { valid: false, reason: "PUBLIC_KEY_FINGERPRINT_MISMATCH", fingerprint };
  if (document.payloadHash !== `sha256:${sha256Hex(canonical)}`) return { valid: false, reason: "PAYLOAD_HASH_MISMATCH", fingerprint };
  try {
    const valid = verify(null, canonical, createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(document.publicKey, "hex")]), format: "der", type: "spki" }), Buffer.from(document.signature, "base64"));
    return { valid, reason: valid ? "VERIFIED" : "SIGNATURE_INVALID", fingerprint };
  } catch {
    return { valid: false, reason: "SIGNATURE_INVALID", fingerprint };
  }
}

export async function fetchQuantusWitnessStatus(endpoint) {
  const url = new URL("/v1/health", endpoint).toString();
  const response = await fetch(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(10000), headers: { Accept: "application/json" } });
  const body = await response.text();
  let parsed = null;
  try { parsed = JSON.parse(body); } catch {}
  return { url, statusCode: response.status, bodySha256: sha256Hex(body), parsed };
}
