const { buildSync } = require('esbuild');
const { spawnSync } = require('child_process');
const { mkdirSync } = require('fs');
mkdirSync('output', { recursive: true });
buildSync({ entryPoints: ['tests/services.test.ts'], outfile: 'output/services.test.cjs', bundle: true, platform: 'node', format: 'cjs' });
const result = spawnSync(process.execPath, ['--test-reporter=tap', 'output/services.test.cjs'], { stdio: 'inherit' });
process.exitCode = result.status ?? 1;
