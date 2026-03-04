# FreightLogic v14.3.4-hardened — Certification Report

This build is a patch release over v14.3.2 (Nav upgrade) focused on:
- CSP-compliant navigation card (removed inline onclick; restored #homeOmegaCard id)
- Service worker + audit tooling version alignment

Run:
- `node red_team_certify_v14_3_3.js`
- `node red_team_audit.js`

Expected: 0 failures (warnings may occur only for dynamic IDs).
