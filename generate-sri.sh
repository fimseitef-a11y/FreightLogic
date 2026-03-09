#!/bin/bash
# FreightLogic — SRI Hash Generator
# Run this script to generate Subresource Integrity hashes for CDN dependencies.
# Then paste the output into app.js loadSheetJS() and loadTesseract() functions.

echo "=== FreightLogic SRI Hash Generator ==="
echo ""

echo "SheetJS (xlsx@0.18.5):"
XLSX_HASH=$(curl -sL https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js | openssl dgst -sha384 -binary | openssl base64 -A)
echo "  s.integrity = 'sha384-${XLSX_HASH}';"
echo ""

echo "Tesseract.js (tesseract.js@5.1.1):"
TESS_HASH=$(curl -sL https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js | openssl dgst -sha384 -binary | openssl base64 -A)
echo "  s.integrity = 'sha384-${TESS_HASH}';"
echo ""

echo "=== Paste these into app.js ==="
echo "1. In loadSheetJS(): uncomment and replace the s.integrity line"
echo "2. In loadTesseract(): uncomment and replace the s.integrity line"
