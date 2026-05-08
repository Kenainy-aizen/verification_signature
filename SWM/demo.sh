#!/usr/bin/env bash
# ============================================================
#  signtool — Demo Script (Linux / macOS / WSL)
#  Demonstrates the full signing workflow
# ============================================================

set -euo pipefail

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RED="\033[31m"
DIM="\033[2m"

STEP=0
total_steps=8

step() {
    STEP=$((STEP + 1))
    echo -e "\n${BOLD}${CYAN}[${STEP}/${total_steps}]${RESET} ${BOLD}$*${RESET}"
}

ok()   { echo -e "   ${GREEN}✓${RESET} $*"; }
info() { echo -e "   ${DIM}$*${RESET}";     }
fail() { echo -e "   ${RED}✗ $*${RESET}"; exit 1; }

# --- Move to script directory --------------------------------
cd "$(dirname "$0")"

echo -e "\n${BOLD}============================================================${RESET}"
echo -e "${BOLD}   signtool Demo — Bash${RESET}"
echo -e "${BOLD}============================================================${RESET}"

# --- Install -------------------------------------------------
step "Installing signtool in editable mode"
pip install -e . --quiet && ok "Installed"

# --- Workspace -----------------------------------------------
DEMO_DIR="demo_workspace"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"/{keys,docs,sigs}

# --- Sample files --------------------------------------------
step "Creating sample files"
echo "Hello, signtool! This is document 1."  > "$DEMO_DIR/docs/document1.txt"
echo "Another document for the signing demo." > "$DEMO_DIR/docs/document2.txt"
echo "Contract v1.0 — CONFIDENTIAL"          > "$DEMO_DIR/docs/contract.txt"
echo "Invoice #2024-001 — Amount: 1500 EUR"  > "$DEMO_DIR/docs/invoice.txt"
ok "Files created in $DEMO_DIR/docs/"

# --- Step 3: keygen (2048 bits) ------------------------------
step "Generating RSA-2048 key pair"
signtool keygen \
    --bits       2048 \
    --output-dir "$DEMO_DIR/keys" \
    --name       mykey

# --- Step 4: keygen (4096 bits) ------------------------------
step "Generating RSA-4096 key pair (stronger)"
signtool keygen \
    --bits       4096 \
    --output-dir "$DEMO_DIR/keys" \
    --name       strongkey

# --- Step 5: Sign single file --------------------------------
step "Signing document1.txt with mykey"
signtool sign \
    --key        "$DEMO_DIR/keys/mykey_private.pem" \
    --file       "$DEMO_DIR/docs/document1.txt" \
    --output-dir "$DEMO_DIR/sigs"

# --- Step 6: Batch sign with glob ----------------------------
step "Batch-signing all .txt files with glob pattern"
signtool sign \
    --key        "$DEMO_DIR/keys/mykey_private.pem" \
    --file       "$DEMO_DIR/docs/document2.txt" \
    --file       "$DEMO_DIR/docs/contract.txt" \
    --file       "$DEMO_DIR/docs/invoice.txt" \
    --output-dir "$DEMO_DIR/sigs"

# --- Step 7: info --------------------------------------------
step "Inspecting document1.txt.sig metadata"
signtool info "$DEMO_DIR/sigs/document1.txt.sig"

# --- Step 8: verify ------------------------------------------
step "Verifying document1.txt (should be VALID)"
if signtool verify \
        --key  "$DEMO_DIR/keys/mykey_public.pem" \
        --file "$DEMO_DIR/docs/document1.txt" \
        --sig  "$DEMO_DIR/sigs/document1.txt.sig"; then
    ok "Verification passed as expected"
else
    fail "Unexpected: verification failed for an unmodified file!"
fi

# --- Tamper detection ----------------------------------------
echo -e "\n${BOLD}${YELLOW}[BONUS]${RESET} ${BOLD}Tamper detection test${RESET}"
echo "TAMPERED CONTENT" >> "$DEMO_DIR/docs/document1.txt"
info "Appended garbage to document1.txt"

if signtool verify \
        --key  "$DEMO_DIR/keys/mykey_public.pem" \
        --file "$DEMO_DIR/docs/document1.txt" \
        --sig  "$DEMO_DIR/sigs/document1.txt.sig" 2>/dev/null; then
    fail "Unexpected: tampered file passed verification!"
else
    ok "Tamper detected as expected — signature INVALID"
fi

# --- Summary -------------------------------------------------
echo -e "\n${BOLD}============================================================${RESET}"
echo -e "${BOLD}${GREEN}   Demo complete!${RESET}"
echo -e "${DIM}   Workspace : $DEMO_DIR/${RESET}"
echo -e "${DIM}   Keys      : $DEMO_DIR/keys/${RESET}"
echo -e "${DIM}   Sigs      : $DEMO_DIR/sigs/${RESET}"
echo -e "${BOLD}============================================================${RESET}\n"
