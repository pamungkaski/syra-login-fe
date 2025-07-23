#!/usr/bin/env bash
#
# download_public.sh
# Downloads the two Google Drive files provided and places them into ./public
# Usage: bash download_public.sh
#
# Requirements:
#   - Either the python package `gdown` must be installed **or** `curl` must be available.
#     The script automatically prefers `gdown` if it exists, otherwise falls back to `curl`.
#   - Write permission for the current directory (to create ./public).
#
# Notes:
#   - If you have many downloads, using `gdown` is generally more reliable for Google Drive.
#   - The fallback `curl` method handles Google's confirmation token for larger files.
#

set -euo pipefail

# Create the target directory if it doesn't exist
mkdir -p ./public

# -------- Helper functions --------
download_with_gdown() {
  local fid="$1"
  echo "[gdown] Downloading file id $fid..."
  gdown --id "$fid" --output ./public/ >/dev/null
}

download_with_curl() {
  local fid="$1"
  local dest="./public/$fid"
  echo "[curl] Downloading file id $fid into $dest..."
  # First request grabs the confirmation token (if needed)
  local confirm
  confirm=$(curl -sc ./cookie "https://drive.google.com/uc?export=download&id=$fid" |             grep -oP 'confirm=\K[^&]*' || true)

  if [[ -n "$confirm" ]]; then
    curl -Lb ./cookie "https://drive.google.com/uc?export=download&confirm=$confirm&id=$fid" -o "$dest"
  else
    # Small files may not require a confirm token
    curl -L "https://drive.google.com/uc?export=download&id=$fid" -o "$dest"
  fi
  rm -f ./cookie
}

download_file() {
  local fid="$1"
  if command -v gdown >/dev/null 2>&1; then
    download_with_gdown "$fid"
  else
    download_with_curl "$fid"
  fi
}

# -------- File IDs to download --------
file_ids=(
  "1LT_rODvKmCVc9O9S39q8xbQUeyQKGBOM"
  "1NV_kyYMsP3sbBPt6z8e0Oz-zyYNi21Ko"
)

# -------- Main loop --------
for fid in "${file_ids[@]}"; do
  download_file "$fid"
done

echo "✅  All files downloaded into ./public"
