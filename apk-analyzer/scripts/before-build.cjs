const { access } = require('fs/promises');
const path = require('path');

// esbuild already bundles all runtime libraries. Only Electron/Node built-ins
// remain external, so electron-builder must not rebuild or copy node_modules.
module.exports = async ({ appDir }) => {
  for (const file of ['dist/main/main.js', 'dist/main/analysisWorker.js', 'dist/preload/preload.js', 'dist/renderer/index.html']) {
    await access(path.join(appDir, file));
  }
  return false;
};
