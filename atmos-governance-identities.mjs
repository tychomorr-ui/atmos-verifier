// Reservations prevent accidental ADMIT as an unknown node; they do not
// enroll a key, establish a URL, or resolve any legacy identity mapping.
export const CANONICAL_NODE_IDS = new Set([
  "ROOT-GATE", "TESSERACT-TERMINUS", "XINUS-CLARITY", "MONARCH-OS", "TESSERACT-A",
  "KEIRA", "VALKYRIE", "ARCHANGEL", "PROJECT-RECLAIM", "IWA-SAGE", "RESONATE-EARTH",
  "QUANTUS", "TESSERACT-MIRROR", "TESSERACT-A-CORE",
]);

export function isCanonicalNodeId(nodeId) {
  return CANONICAL_NODE_IDS.has(nodeId);
}
