# Changelog

All notable changes to Hansen are documented in this file.

## [1.1.1] - 2026-10-14

### Added

- Added an explicit pre-scan checkbox for optional VirusTotal hash checks.
- Added browser-style Back and Forward navigation with restoration of package reports, completed comparisons, find queries, active matches, and highlights.
- Added a hold-to-open Back-history menu with 10 recent entries and a full-history dialog for older entries.
- Added a setting to retain 10, 25, 50, or 100 navigation-history pages.
- Added **Open file** and **Open directory** actions after PDF, JSON, SARIF, and comparison exports.
- Added an in-app scan-label editor. Multiple selected scans receive ordered labels such as `Instagram ApkPure-001` and `Instagram ApkPure-002`.
- Added direct links to VirusTotal API-key settings and completed VirusTotal scan pages.

### Changed

- The Package Inspector navigation item now becomes **New package** while an existing report is open.
- VirusTotal evidence and actions now reflect whether an API key is configured instead of always stating that a key is required.
- When VirusTotal has no matching hash, Hansen can offer to upload the original inspected APK without asking the user to select it again.
- VirusTotal uploads now retain and verify the original package path and exact SHA-256 before submission.
- VirusTotal connection, authentication, quota, timeout, and response failures now provide clearer explanations.
- Navigation-history entries now identify exact package reports, comparison pairs, saved searches, and match positions.
- Report-selection controls now remain on one row.
- The application version is now shown in the About splash opened from the Hansen logo rather than in the top toolbar.
- PDF reports and comparisons now use a dark full-page canvas instead of white outer margins.
- Updated application branding, README screenshots, and release metadata for version 1.1.1.

### Fixed

- Fixed Back navigation returning to an empty comparison tab instead of the previously viewed comparison.
- Fixed find highlights and match progress being lost after navigating to another report.
- Fixed the Back-history menu extending outside the application window.
- Fixed the missing shared border between the Back and Forward buttons.
- Fixed **Edit label** doing nothing in Electron because it relied on an unsupported browser prompt.
- Fixed valid obfuscated APKs being rejected when resource paths differed only by letter case.
- Exact duplicate archive paths remain rejected with a detailed explanation because their contents are ambiguous.
- Fixed exported PDF page margins displaying as white around the dark report design.

### Security and privacy

- VirusTotal remains opt-in for each inspection, and APK uploads still require explicit confirmation.
- Direct APK upload uses only bytes that match the saved report and selected package hash.
- Export-opening actions are restricted to files Hansen exported during the current application session.
- External VirusTotal links remain limited to approved HTTPS destinations.

### Validation

- TypeScript validation passes.
- Production main-process, preload, worker, CLI, and renderer builds pass.
- All 26 automated service tests pass.
- The corrected 12-page PDF export was rendered and visually reviewed page by page.
