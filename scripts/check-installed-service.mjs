import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));
const fixture = mkdtempSync(join(tmpdir(), 'evidence-installed-service-'));
const run = (file, args, cwd) => execFileSync(file, args, {
  cwd, stdio: 'inherit', timeout: 240_000,
});
const replaceOnce = (source, needle, replacement) => {
  assert.equal(source.split(needle).length, 2, 'Expected one fixture adaptation');
  return source.replace(needle, () => replacement);
};

try {
  const pkg = JSON.parse(readFileSync(join(repository, 'package.json'), 'utf8'));
  // npm pack runs the ordinary prepare/build. The installed consumer uses only public exports.
  run('npm', ['pack', '--pack-destination', fixture], repository);
  const archives = readdirSync(fixture).filter(name => name.endsWith('.tgz'));
  assert.equal(archives.length, 1, 'One packed engine required');
  const devDependencies = Object.fromEntries(
    ['typescript', '@types/node', '@types/pg']
      .filter(name => Object.hasOwn(pkg.devDependencies, name))
      .map(name => [name, pkg.devDependencies[name]]),
  );
  assert(devDependencies.typescript && devDependencies['@types/node']);
  assert(pkg.devDependencies['@electric-sql/pglite']);
  writeFileSync(join(fixture, 'package.json'), JSON.stringify({
    name: 'evidence-installed-service-fixture',
    private: true,
    type: 'module',
    dependencies: {
      '@accountability/evidence': 'file:' + join(fixture, archives[0]),
      '@electric-sql/pglite': pkg.devDependencies['@electric-sql/pglite'],
    },
    devDependencies,
  }, null, 2) + '\n');

  let tests = readFileSync(join(repository, 'tests/service.test.ts'), 'utf8');
  // Credential hashes are fixture setup, not an import of the private Identity implementation.
  tests = replaceOnce(tests, "import {tokenHash} from '../src/identity-sdk.ts';",
    "const tokenHash=(token:string)=>createHash('sha256').update(token).digest('hex');");
  tests = tests.replace(/(["'])\.\.\/src\/([^"']+)\.ts\1/g,
    (_match, quote, name) => quote + '@accountability/evidence' +
      (name === 'index' ? '' : '/' + name) + quote);
  tests = replaceOnce(tests,
    "new URL('../migrations/001_foundation.sql',import.meta.url)",
    "new URL('./node_modules/@accountability/evidence/migrations/001_foundation.sql',import.meta.url)");
  assert(!tests.includes('../src/'), 'Installed fixture must not import source');
  assert(!tests.includes('@accountability/evidence/identity-sdk'),
    'Installed fixture must not import a private package path');
  writeFileSync(join(fixture, 'service.test.ts'), tests);

  // No ignore-scripts: pinned Git SDK dependencies require normal preparation.
  run('npm', ['install', '--include=dev', '--no-audit', '--no-fund'], fixture);
  assert.deepEqual(
    readFileSync(join(fixture, 'node_modules/@accountability/evidence/dist/service.js')),
    readFileSync(join(repository, 'dist/service.js')),
    'Installed service bytes differ from the prepared source build',
  );
  run(process.execPath, [
    join(fixture, 'node_modules/typescript/bin/tsc'),
    '--noEmit', '--module', 'NodeNext', '--moduleResolution', 'NodeNext',
    '--target', 'ES2023', '--strict', '--skipLibCheck', '--types', 'node', 'service.test.ts',
  ], fixture);
  console.log('Running installed compiled public-export service tests in an isolated fixture');
  run(process.execPath, ['--test', 'service.test.ts'], fixture);
  console.log('Installed service exports, declaration compilation and module byte match passed');
} finally {
  // Delete only this invocation's newly created disposable fixture.
  rmSync(fixture, { recursive: true, force: true });
}
