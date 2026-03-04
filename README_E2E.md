# Playwright E2E (FreightLogic)

This folder adds end-to-end browser tests using Playwright.

## Prereqs
- Node.js 18+ recommended

## Install
```bash
npm install
npm run e2e:install-browsers
```

## Run tests
```bash
npm test
```

## Run headed (watch it)
```bash
npm run test:headed
```

## Notes
- Tests start a static server at http://127.0.0.1:4173 using `http-server`.
- The suite runs in Chromium, WebKit, and an iPhone 13 device profile.
