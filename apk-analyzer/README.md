# Hansen

Hansen is a desktop application for static inspection of Android APK and XAPK packages. Reports are available in the application and can be exported as PDF.

## Build

Requires Node.js 22.12 or later and npm 10 or later. The repository selects Node.js 24 through `.nvmrc`. If your terminal uses an older version, follow the [Node.js setup instructions](LAUNCH_GUIDE.md#nodejs-setup) before installing dependencies.

```bash
npm ci --include=optional
npm run build
npm start
```

Run `npm run dev` to develop the renderer. Local analysis is the default. Optional AI interpretation is configured in application settings.

## Documentation

Read [Getting Started](GETTING_STARTED.md), [Architecture](ARCHITECTURE.md), and [Launch Guide](LAUNCH_GUIDE.md). [Validation Results](TEST_RESULTS.md) records the tested APK and build details.

## Scope

The report summarizes manifest data and bounded static string matches. It does not execute Android code or certify that a package is safe. See each report for its scan coverage and limitations.

## License

Apache License 2.0. See the repository [LICENSE](../LICENSE).
