#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${1:-./data}"
OUT_DIR="${2:-./evidence}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BUNDLE_NAME="evidence_${TIMESTAMP}.tar.gz"

mkdir -p "${OUT_DIR}"
echo "[*] Creating evidence bundle for ${DATA_DIR} -> ${OUT_DIR}/${BUNDLE_NAME}"

# create tarball
tar -czf "${OUT_DIR}/${BUNDLE_NAME}" -C "${DATA_DIR}" .

# compute SHA256 for each file in data and for bundle
echo "[*] Computing SHA256s..."
cd "${DATA_DIR}"
find . -type f -print0 | while IFS= read -r -d '' f; do
  sha256sum "$f"
done > "${OUT_DIR}/file_shas_${TIMESTAMP}.txt"
cd - >/dev/null

sha256sum "${OUT_DIR}/${BUNDLE_NAME}" > "${OUT_DIR}/${BUNDLE_NAME}.sha256"

# create manifest.json (simple)
python3 - <<PY
import json,os,hashlib,sys
outdir = os.path.abspath("${OUT_DIR}")
data_dir = os.path.abspath("${DATA_DIR}")
manifest = {
  "bundle": os.path.basename("${BUNDLE_NAME}"),
  "bundle_sha256": open(os.path.join(outdir, "${BUNDLE_NAME}.sha256")).read().strip().split()[0],
  "files": []
}
# load file_shas
with open(os.path.join(outdir, "file_shas_${TIMESTAMP}.txt")) as fh:
    for line in fh:
        sha, path = line.strip().split(None,1)
        manifest["files"].append({"path": path, "sha256": sha})
with open(os.path.join(outdir, "manifest_${TIMESTAMP}.json"), "w") as mf:
    json.dump(manifest, mf, indent=2)
print("[*] Wrote manifest:", os.path.join(outdir, "manifest_${TIMESTAMP}.json"))
PY

# optional: GPG sign (if GPG key is available)
if command -v gpg >/dev/null 2>&1; then
  echo "[*] GPG found. Creating detached signature for manifest..."
  gpg --armor --output "${OUT_DIR}/manifest_${TIMESTAMP}.json.asc" --detach-sign "${OUT_DIR}/manifest_${TIMESTAMP}.json"
  echo "[*] Created signature manifest_${TIMESTAMP}.json.asc"
else
  echo "[!] gpg not installed or not in PATH. Skipping signature. To sign: gpg --armor --detach-sign manifest_${TIMESTAMP}.json"
fi

echo "[*] Evidence bundle created: ${OUT_DIR}/${BUNDLE_NAME}"
echo "[*] SHA file: ${OUT_DIR}/${BUNDLE_NAME}.sha256"
echo "[*] Manifest: ${OUT_DIR}/manifest_${TIMESTAMP}.json"

