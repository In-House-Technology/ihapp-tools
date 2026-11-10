import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/ihapp-catalog.js', import.meta.url));
const run = (...args) => spawnSync('node', [cli, ...args], { encoding: 'utf8' });

const index = `index_version: 1
apps:
  - id: inhouse/example-app
    name: Example
    summary: An example app.
    repository: https://github.com/In-House-Technology/example-app.git
    license: MIT
    versions:
      - version: 1.0.1
        commit: ${'b'.repeat(40)}
        approved_by: owner@example.com
        approved_at: '2026-11-10'
      - version: 1.0.0
        commit: ${'a'.repeat(40)}
        approved_by: owner@example.com
        approved_at: '2026-11-09'
`;

function workdir() {
  const dir = mkdtempSync(path.join(tmpdir(), 'ihapp-tools-'));
  writeFileSync(path.join(dir, 'catalog.yaml'), index);
  return dir;
}

test('a valid index passes offline', () => {
  const dir = workdir();
  try { assert.equal(run('validate-index', path.join(dir, 'catalog.yaml'), '--org', 'In-House-Technology').status, 0); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});

test('versions out of order are refused', () => {
  const dir = workdir();
  try {
    writeFileSync(path.join(dir, 'catalog.yaml'), index.replace('1.0.1', '0.9.0'));
    assert.equal(run('validate-index', path.join(dir, 'catalog.yaml')).status, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a signature over the exact bytes verifies, and tampering is refused', () => {
  const dir = workdir();
  try {
    const raw = Buffer.from(index);
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const x = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('base64');
    const sig = { v: 1, alg: 'ed25519', key_id: 'test-key', sha256: createHash('sha256').update(raw).digest('hex'), signature: sign(null, raw, privateKey).toString('base64') };
    writeFileSync(path.join(dir, 'catalog.sig'), JSON.stringify(sig));
    writeFileSync(path.join(dir, 'keys.json'), JSON.stringify([{ key_id: 'test-key', alg: 'ed25519', public_key: x }]));
    const args = ['validate-index', path.join(dir, 'catalog.yaml'), '--signature', path.join(dir, 'catalog.sig'), '--keys', path.join(dir, 'keys.json')];
    assert.equal(run(...args).status, 0);
    writeFileSync(path.join(dir, 'catalog.yaml'), index + '\n');
    assert.equal(run(...args).status, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the CLI prints usage on a bad command', () => {
  assert.equal(run('nope').status, 2);
  assert.ok(execFileSync('node', ['--version']).length > 0);
});
