Optional offline vendor files
============================

Drop these exact files here if you want Excel import and OCR to work with no internet:

1) xlsx.full.min.js
   Source version: xlsx@0.18.5/dist/xlsx.full.min.js

2) tesseract.min.js
   Source version: tesseract.js@5.1.1/dist/tesseract.min.js

3) worker.min.js
   Source version: tesseract.js@5.1.1/dist/worker.min.js

4) tesseract-core-simd-lstm.wasm.js
   Source version: tesseract.js-core@5.1.0/tesseract-core-simd-lstm.wasm.js

Behavior:
- If these files exist locally, FreightLogic uses them first.
- If they do not exist, FreightLogic falls back to the CDN.
- Core app features work without these files.
