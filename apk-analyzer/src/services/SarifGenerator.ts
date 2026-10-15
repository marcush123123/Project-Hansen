import { AnalysisReport } from '../types';

const level = (severity: string) => severity === 'high' ? 'error' : severity === 'medium' ? 'warning' : 'note';
export class SarifGenerator {
  static build(report: AnalysisReport) {
    const findings = [...(report.malware?.localFindings || []), ...report.findings];
    const rules = [...new Map(findings.map(f => [f.id, {
      id: f.id, name: f.title.replace(/[^A-Za-z0-9]+/g, '_'), shortDescription: { text: f.title },
      fullDescription: { text: f.detail }, help: { text: f.recommendation },
      defaultConfiguration: { level: level(f.severity) }, properties: { category: 'Android package inspection', severity: f.severity },
    }])).values()];
    return {
      version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{
        tool: { driver: { name: 'Hansen', informationUri: 'https://github.com/', version: '1.1.1', rules } },
        artifacts: [{ location: { uri: report.fileName }, hashes: { sha256: report.sha256 }, properties: { packageName: report.context.packageName, versionCode: report.context.versionCode } }],
        results: findings.map(f => ({ ruleId: f.id, level: level(f.severity), message: { text: `${f.detail} Review action: ${f.recommendation}` }, locations: [{ physicalLocation: { artifactLocation: { uri: report.fileName } } }], properties: { evidence: f.evidence, reportId: report.id } })),
        properties: { hansenReportId: report.id, malwareVerdict: report.malware?.verdict || 'not-assessed', configurationScore: report.assessment.safetyScore, telemetryScore: report.assessment.transparencyScore },
      }],
    };
  }
}
