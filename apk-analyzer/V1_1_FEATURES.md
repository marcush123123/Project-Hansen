# Hansen 1.1 feature program

Hansen 1.1 focuses on change-aware, local Android package review: verify the available signing identity, compare releases, and export evidence without installing the package.

## Implemented in 1.1

1. **Signing identity and provenance**
   - Detects JAR/v1 and APK Signature Scheme v2, v3, and v3.1 structures.
   - Extracts modern signing certificates, SHA-256 fingerprints, subject/issuer, validity dates, serial number, and public-key type.
   - Preserves an explicit distinction between extracted identity and cryptographic signature verification.

2. **Release comparison workspace**
   - Compares two saved reports, with same-package validation and signer-continuity status.
   - Diffs permissions, exported components, trackers, network origins, code capabilities, findings, and APK splits.
   - Shows file-size, DEX, native-library, configuration-score, and telemetry-score deltas.
   - Exports the comparison as JSON or PDF.

3. **Deeper component exposure analysis**
   - Retains intent actions, intent categories, deep links, provider read/write permissions, and URI-grant configuration.
   - Uses provider-specific guards when deciding whether an exported component is unprotected.

4. **Explainable permissions and trackers**
   - Adds capability, purpose, and review context for sensitive Android permissions.
   - Adds tracker vendor and typical-purpose metadata while labeling namespace matches as inclusion evidence rather than observed collection.

5. **Developer exports and headless analysis**
   - Adds stable JSON and SARIF 2.1 exports.
   - Adds `npm run analyze -- <package> --format json|sarif --output <file>` for local headless scans.

6. **Report management and usability**
   - Increases local history retention from 20 to 100 reports.
   - Adds history filtering, explicit report deletion, report version labels, and JSON/SARIF export actions.
   - Adds signing identity to HTML and PDF reports.

## Proposed follow-on work

These ideas remain valuable, but need more design or validation than should be hidden inside the 1.1 scope:

- Full cryptographic APK signature verification and proof-of-rotation lineage validation.
- Compiled `network_security_config` and backup-rule resource resolution.
- First-party/third-party domain ownership and optional geographic enrichment.
- Privacy-policy and app-store disclosure comparison.
- User-managed allowlists, time-bounded suppressions, and CI failure policies.
- Import/export of complete portable Hansen report bundles.
- Rule-version migrations and guided rescans when the original package is available.
- A maintained external tracker-definition update channel.
- Guided emulator/runtime traffic capture as a separate, isolated workflow.
- Android App Bundle, iOS, crowdsourced reputation, and organizational dashboards.

Hansen will continue to avoid an unsupported universal “safe/unsafe” verdict. Static findings and comparisons are decision support, not proof of runtime behavior or certification against OWASP MASVS.
