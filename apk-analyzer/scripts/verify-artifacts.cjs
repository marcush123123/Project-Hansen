const { createHash } = require('crypto');
const { readdir, readFile, stat, writeFile } = require('fs/promises');
const path = require('path');

const { version } = require('../package.json');
const escapedVersion = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const targets = {
  'linux-x64': [
    new RegExp(`^Hansen-${escapedVersion}-linux-x86_64\\.AppImage$`),
  ],
  'windows-x64': [
    new RegExp(`^Hansen-${escapedVersion}-windows-x64-setup\\.exe$`),
    new RegExp(`^Hansen-${escapedVersion}-windows-x64-portable\\.exe$`),
  ],
  'mac-x64': [
    new RegExp(`^Hansen-${escapedVersion}-mac-x64\\.dmg$`),
    new RegExp(`^Hansen-${escapedVersion}-mac-x64\\.zip$`),
  ],
  'mac-arm64': [
    new RegExp(`^Hansen-${escapedVersion}-mac-arm64\\.dmg$`),
    new RegExp(`^Hansen-${escapedVersion}-mac-arm64\\.zip$`),
  ],
};

async function main() {
  const target = process.argv[2];
  const expected = targets[target];
  if (!expected) throw new Error(`Usage: npm run verify:artifacts -- ${Object.keys(targets).join('|')}`);

  const buildDir = path.resolve('build');
  const entries = await readdir(buildDir);
  const files = [];
  for (const pattern of expected) {
    const matches = entries.filter(name => pattern.test(name));
    if (matches.length !== 1) throw new Error(`Expected exactly one artifact matching ${pattern}; found ${matches.length}: ${matches.join(', ') || 'none'}`);
    const name = matches[0];
    const info = await stat(path.join(buildDir, name));
    if (!info.isFile() || info.size === 0) throw new Error(`Artifact is missing or empty: ${name}`);
    files.push(name);
  }
  const installers = entries.filter(name => /^Hansen-.*-(?:linux|windows|mac)-.*\.(?:AppImage|exe|dmg|zip)$/i.test(name));
  const unexpected = installers.filter(name => !files.includes(name));
  if (unexpected.length) throw new Error(`Unexpected installer artifact(s) for ${target}: ${unexpected.join(', ')}`);

  const checksumLines = [];
  for (const name of files.sort()) {
    const digest = createHash('sha256').update(await readFile(path.join(buildDir, name))).digest('hex');
    checksumLines.push(`${digest}  ${name}`);
  }
  const checksumName = `SHA256SUMS-${target}.txt`;
  await writeFile(path.join(buildDir, checksumName), `${checksumLines.join('\n')}\n`, 'utf8');
  console.log(`Verified ${files.length} artifact(s) and wrote build/${checksumName}`);
}

main().catch(error => {
  console.error(error.message || error);
  process.exitCode = 1;
});
