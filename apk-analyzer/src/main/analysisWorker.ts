import { parentPort, workerData } from 'worker_threads';
import { analyzeApkWorkflow } from './apkAnalyzer';
analyzeApkWorkflow(workerData.input, workerData.settings, workerData.tempDir, progress => parentPort?.postMessage({ progress }))
  .then(report => parentPort?.postMessage({ report }))
  .catch(error => parentPort?.postMessage({ error: error instanceof Error ? error.message : 'Analysis failed' }));
