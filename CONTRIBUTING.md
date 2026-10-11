# Contributing

Use Node.js 22.12 or later and npm 10 or later. From `apk-analyzer`, install the optional platform dependencies, then run the checks and renderer build:

```bash
npm ci --include=optional
npm run typecheck
npm test
npm run build:vite
```

Keep changes focused. Update the relevant documentation when behavior changes. Do not commit APKs, XAPKs, credentials, reports, build output, or personal data. Bug reports should include reproducible steps and the application version, without confidential package contents.
