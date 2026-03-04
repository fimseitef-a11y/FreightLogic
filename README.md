# FreightLogic (v14.3.4-hardened)

Offline-first PWA for expeditor / cargo-van operations (Trips, Expenses, Fuel, KPIs, Midwest Stack, Omega tiers).

## Run locally

```bash
# from repo root
npx http-server -p 5173
```

Open: http://localhost:5173/index.html#home

## Run audits

```bash
node audits/red_team_audit.js
node audits/red_team_certify_v14_3_4.js
node --check app.js
```

## Run Playwright E2E

```bash
npm install
npx playwright install
npm test
```
