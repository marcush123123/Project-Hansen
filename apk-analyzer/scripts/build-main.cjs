const esbuild = require('esbuild');
const { builtinModules } = require('module');
const builtins = new Set([...builtinModules, ...builtinModules.map(name => `node:${name}`), 'electron']);
const options = { entryPoints: ['src/main/main.ts', 'src/main/analysisWorker.ts', 'src/preload/preload.ts', 'src/cli.ts'], outbase: 'src', outdir: 'dist', bundle: true, platform: 'node', format: 'cjs', target: 'node22', external: ['electron'], sourcemap: true, metafile: true };
esbuild.build(options).then(result => {
  for (const output of Object.values(result.metafile.outputs)) {
    for (const entry of output.imports) {
      if (entry.external && !builtins.has(entry.path)) throw new Error(`Unbundled runtime dependency: ${entry.path}`);
    }
  }
}).catch(error => { console.error(error); process.exitCode = 1; });
