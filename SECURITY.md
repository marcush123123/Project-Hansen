# Security policy

Hansen inspects untrusted Android packages. Static indicators do not establish that an application is safe or malicious.

Local malware rules identify capability combinations and can produce false positives. VirusTotal results are attributed to their reporting engines and do not constitute certification. Unavailable, stale, pending and incomplete reputation checks cannot produce a completed negative assessment. Configuration grades and AI commentary do not override malware findings.

VirusTotal integration is opt-in and shares APK hashes. Full APK submission requires a separate confirmation for each selected file and can result in retention or sharing by VirusTotal. Do not upload confidential software. Files and reports are hashed and matched before upload; Android code is never executed by Hansen. API keys are encrypted through the operating system where supported, otherwise retained in memory for the session. Reports themselves are not encrypted.

Please report vulnerabilities through GitHub's private vulnerability reporting feature. Do not include APK files, API keys, personal data, or confidential reports in public issues. Include the affected version, the relevant component, and steps to reproduce without sharing sensitive package contents.

Security reports are reviewed as maintainers are available. No response time or supported version window is guaranteed.
