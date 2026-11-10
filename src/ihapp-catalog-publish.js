import { readFileSync, lstatSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import YAML from 'yaml';
import { catalogSchema, catalogAjv } from './ihapp-catalog-schema.js';
import { validateCatalogManifest, permissionsOf, permissionsWidened } from './ihapp-catalog.js';
import { detectLicense } from './ihapp-catalog-license.js';
import { verifyCatalogSignature } from './ihapp-catalog-keys.js';

const ajv = catalogAjv();
const manifestSchemaId = catalogSchema('ihapp-catalog').$id;
const schemaId = manifestSchemaId.slice(0, manifestSchemaId.lastIndexOf('/') + 1);
const manifestSchema = ajv.getSchema(`${schemaId}ihapp-catalog.schema.json#/$defs/CatalogManifest`);
const indexSchema = ajv.getSchema(`${schemaId}ihapp-catalog-index.schema.json`);
const companySchema = ajv.compile(catalogSchema('company-app'));
const issue = (code, message, path = '') => ({ code: `IHC-CATALOG-${code}`, message, path });
const dummy = { __APP_SLUG__: 'catalog-app', __APP_NAME__: 'Catalog app', __OWNER_EMAIL__: 'owner@example.com',
  __APP_DOMAIN__: 'catalog-app.cloud.localhost', __APP_GROUP__: 'ihc-users' };
const fill = text => Object.entries(dummy).reduce((s, [key, value]) => s.replaceAll(key, value), text);

function localRepository(repository) {
  if (typeof repository !== 'string') return false;
  if (path.isAbsolute(repository) || /^\.{1,2}\//.test(repository)) return true;
  try { return repository.startsWith('file://') && path.isAbsolute(fileURLToPath(repository)); } catch { return false; }
}

function structural(validate, value, allowLocal = false, index = false) {
  // The published schema requires HTTPS. Local transports are an explicit offline
  // --fetch convenience; all other fields still undergo exactly that schema.
  const input = structuredClone(value);
  if (allowLocal && input && typeof input === 'object') {
    const entries = index ? (Array.isArray(input.apps) ? input.apps : []) : [input.origin];
    for (const entry of entries) {
      if (entry && localRepository(entry.repository)) entry.repository = 'https://example.com/offline.git';
    }
  }
  if (validate(input)) return [];
  return validate.errors.map(e => issue('SCHEMA', e.message, e.instancePath));
}

function parse(read, name, findings, substitute = false) {
  try {
    const text = read(name);
    if (text === undefined) { findings.push(issue('FILE', `Missing ${name}.`, '')); return; }
    return YAML.parse(substitute ? fill(text) : text, { maxAliasCount: 100 });
  } catch {
    findings.push(issue('FILE', `Cannot read or parse ${name}.`, ''));
  }
}

function manifestOf(read, findings, allowLocal = false) {
  const manifest = parse(read, 'ihapp-catalog.yaml', findings);
  const errors = structural(manifestSchema, manifest, allowLocal);
  findings.push(...errors);
  if (errors.length) return;
  findings.push(...validateCatalogManifest(manifest));
  return manifest;
}

// Both filesystem and Git-object readers use the same validation, without running
// application code or checking out untrusted symlinks and submodules.
export function validateTree(read, { allowLocal = false } = {}) {
  const findings = [];
  for (const name of ['ihapp-config.yaml', 'ihapp-origin.yaml']) {
    try { if (read(name) !== undefined) findings.push(issue('ORIGIN-FILE', `Origin must not ship ${name}.`, '')); }
    catch { findings.push(issue('ORIGIN-FILE', `Origin must not ship ${name}.`, '')); }
  }
  const manifest = manifestOf(read, findings, allowLocal);
  if (!manifest) return { findings };
  const app = parse(read, 'company-app.yaml', findings, true);
  if (!app || typeof app !== 'object' || Array.isArray(app)) {
    findings.push(issue('REQUIRES', 'company-app.yaml must be an object.', '/requires'));
  } else {
    findings.push(...structural(companySchema, app));
    // requires.spec_version is the minimum In House Apps spec, not the separate
    // company-app schema_version. The currently implemented app spec is v1.
    if (manifest.requires.spec_version > 1) findings.push(issue('REQUIRES', 'This validator supports app spec version 1.', '/requires/spec_version'));
    const starterFile = manifest.requires.starter === 'node-minimal' ? 'package.json' : 'backend/requirements.txt';
    if (read(starterFile) === undefined) findings.push(issue('REQUIRES', `Selected starter needs ${starterFile}.`, '/requires/starter'));
    try {
      const actual = permissionsOf(app, manifest.permissions);
      for (const key of ['database', 'redis', 'object_storage']) {
        if (manifest.requires[key] !== actual.data[key]) findings.push(issue('REQUIRES', `${key} must agree with company-app.yaml.`, `/requires/${key}`));
      }
      if (permissionsWidened(manifest.permissions, actual).length || permissionsWidened(actual, manifest.permissions).length) {
        findings.push(issue('PERMISSIONS', 'Declared permissions must agree with company-app.yaml (reasons and order excluded).', '/permissions'));
      }
    } catch {
      findings.push(issue('PERMISSIONS', 'Cannot derive permissions from company-app.yaml.', '/permissions'));
    }
  }
  let license;
  try { license = detectLicense(read('LICENSE') ?? ''); } catch { /* Report as unrecognized. */ }
  if (!license) findings.push(issue('LICENSE', 'LICENSE is missing or its text is unrecognized.', '/license'));
  else if (license !== manifest.license) findings.push(issue('LICENSE', `LICENSE text is ${license}, but manifest declares ${manifest.license}.`, '/license'));
  return { manifest, findings };
}

function diskReader(dir) {
  return name => {
    const file = path.join(dir, name);
    try {
      if (!lstatSync(file).isFile()) throw new Error('Expected regular file');
      return readFileSync(file, 'utf8');
    } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  };
}

function git(dir, ...args) {
  return execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-C', dir, ...args], {
    encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' },
  }).trimEnd();
}

function tagFindings(dir, tag, commit, manifest) {
  const findings = [];
  try {
    const actual = git(dir, 'rev-parse', '--verify', '--end-of-options', `refs/tags/${tag}^{commit}`);
    if (actual !== commit.toLowerCase()) findings.push(issue('COMMIT', 'Tag does not resolve to the pinned commit.', '/commit'));
  } catch { findings.push(issue('TAG', 'Version tag is missing or does not resolve to a commit.', '/version')); }
  if (manifest && tag !== `${manifest.origin.tag_prefix ?? 'v'}${manifest.version}`) findings.push(issue('TAG', 'Tag must equal origin.tag_prefix plus manifest version.', '/version'));
  return findings;
}

export function validateOrigin(dir, { tag, commit } = {}) {
  try {
    const { findings, manifest } = validateTree(diskReader(path.resolve(dir)));
    if (tag !== undefined && commit !== undefined) findings.push(...tagFindings(dir, tag, commit, manifest));
    return findings;
  } catch { return [issue('FILE', 'Cannot read the origin tree.')]; }
}

const compareVersions = (a, b) => {
  const aa = a.split('.').map(BigInt), bb = b.split('.').map(BigInt);
  for (let i = 0; i < 3; i++) if (aa[i] !== bb[i]) return aa[i] > bb[i] ? 1 : -1;
  return 0;
};

export function validateIndex(index, { org, allowLocal = false } = {}) {
  const findings = structural(indexSchema, index, allowLocal, true);
  if (findings.length) return findings;
  const ids = new Set();
  index.apps.forEach((app, i) => {
    const base = `/apps/${i}`;
    if (ids.has(app.id)) findings.push(issue('INDEX-ID', 'App ids must be unique.', `${base}/id`));
    ids.add(app.id);
    if (org) {
      const prefix = `https://github.com/${org}/`;
      if (!app.repository.startsWith(prefix) || !/^[A-Za-z0-9_.-]+\.git$/.test(app.repository.slice(prefix.length))) {
        findings.push(issue('REPOSITORY', `Repository must be https://github.com/${org}/<name>.git.`, `${base}/repository`));
      }
    }
    const versions = new Set();
    app.versions.forEach((release, j) => {
      const where = `${base}/versions/${j}/version`;
      if (versions.has(release.version)) findings.push(issue('INDEX-VERSION', 'Versions must be unique.', where));
      versions.add(release.version);
      if (j && compareVersions(app.versions[j - 1].version, release.version) < 0) findings.push(issue('INDEX-ORDER', 'Versions must be descending by semantic version.', where));
    });
  });
  return findings;
}

function gitReader(repo, commit) {
  return name => {
    const entry = git(repo, 'ls-tree', commit, '--', name);
    if (!entry) return;
    if (!/^100(644|755) blob /.test(entry)) throw new Error('Expected regular file');
    return git(repo, 'show', `${commit}:${name}`);
  };
}

function fetchedFindings(index, dir) {
  const findings = [], repos = new Map();
  index.apps.forEach((app, i) => {
    const base = `/apps/${i}`;
    let repo = repos.get(app.repository);
    if (!repo) {
      repo = path.join(dir, `repo-${repos.size}.git`);
      const source = localRepository(app.repository) && !app.repository.startsWith('file://') ? path.resolve(app.repository) : app.repository;
      try { git(dir, 'clone', '--bare', '--depth=1', '--no-single-branch', '--', source, repo); }
      catch { findings.push(issue('FETCH', 'Cannot clone repository.', `${base}/repository`)); return; }
      repos.set(app.repository, repo);
    }
    app.versions.forEach((release, j) => {
      const where = `${base}/versions/${j}`;
      const tag = `${app.tag_prefix ?? 'v'}${release.version}`;
      // Fetch older tags explicitly: a shallow clone need not contain them.
      try { git(repo, 'fetch', '--depth=1', 'origin', `+refs/tags/${tag}:refs/tags/${tag}`); }
      catch { findings.push(issue('TAG', 'Cannot fetch version tag.', `${where}/version`)); return; }
      const tags = tagFindings(repo, tag, release.commit);
      findings.push(...tags.map(f => ({ ...f, path: where + f.path })));
      if (tags.length) return;
      try {
        const read = gitReader(repo, release.commit);
        const result = j === 0 ? validateTree(read, { allowLocal: true }) : (() => {
          const errors = []; const manifest = manifestOf(read, errors, true); return { manifest, findings: errors };
        })();
        findings.push(...result.findings.map(f => ({ ...f, path: where + f.path })));
        const m = result.manifest;
        if (!m) return;
        for (const [key, actual, expected] of [
          ['id', m.id, app.id], ['version', m.version, release.version],
          ['origin/repository', m.origin.repository, app.repository], ['origin/tag_prefix', m.origin.tag_prefix ?? 'v', app.tag_prefix ?? 'v'],
          ...(j === 0 ? ['name', 'summary', 'categories', 'license'].map(key => [key, m[key], app[key]]) : []),
        ]) {
          if (JSON.stringify(actual) !== JSON.stringify(expected)) findings.push(issue('INDEX-MANIFEST', `${key} must agree with the index.`, `${where}/${key}`));
        }
      } catch { findings.push(issue('FILE', 'Cannot read the version tree.', where)); }
    });
  });
  return findings;
}

export function validateIndexFile(file, { fetch: fetchRepositories = false, org, signature, keys } = {}) {
  let raw, index;
  try { raw = readFileSync(file); }
  catch { return [issue('FILE', 'Cannot read the catalog index.')]; }
  if (signature !== undefined || keys !== undefined) {
    try { verifyCatalogSignature(raw, JSON.parse(readFileSync(signature, 'utf8')), JSON.parse(readFileSync(keys, 'utf8'))); }
    catch { return [issue('SIGNATURE', 'Cannot verify the catalog index signature with the supplied keys.')]; }
  }
  try { index = YAML.parse(raw.toString('utf8'), { maxAliasCount: 100 }); }
  catch { return [issue('FILE', 'Cannot read or parse the catalog index.')]; }
  const findings = validateIndex(index, { org, allowLocal: fetchRepositories });
  if (findings.length || !fetchRepositories) return findings;
  // Checkout-local working directory, always removed; no artifacts left in /tmp.
  const dir = mkdtempSync(path.join(process.cwd(), '.ihapp-catalog-'));
  try { return fetchedFindings(index, dir); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}

export function catalogMain(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const [command, target, ...flags] = args;
  const options = {};
  const allowed = command === 'validate' ? ['tag', 'commit', 'json'] : command === 'validate-index' ? ['fetch', 'org', 'json', 'signature', 'keys'] : [];
  let valid = allowed.length && target && !target.startsWith('--');
  for (let i = 0; i < flags.length; i++) {
    const key = flags[i].slice(2);
    if (!flags[i].startsWith('--') || !allowed.includes(key) || Object.hasOwn(options, key)) { valid = false; break; }
    if (['json', 'fetch'].includes(key)) options[key] = true;
    else {
      const value = flags[++i];
      if (!value || value.startsWith('--')) { valid = false; break; }
      options[key] = value;
    }
  }
  if ((options.tag === undefined) !== (options.commit === undefined) ||
      (options.signature === undefined) !== (options.keys === undefined) ||
      (options.commit && !/^[0-9a-fA-F]{40}$/.test(options.commit)) ||
      (options.org && !/^[A-Za-z0-9][A-Za-z0-9-]*$/.test(options.org))) valid = false;
  if (!valid) {
    stderr.write('Usage: ihapp-catalog.js validate <app-dir> [--tag <tag> --commit <40hex>] [--json]\n       ihapp-catalog.js validate-index <catalog.yaml> [--signature <file.sig> --keys <keys.json>] [--fetch] [--org <org>] [--json]\n');
    return 2;
  }
  let findings;
  try { findings = command === 'validate' ? validateOrigin(target, options) : validateIndexFile(target, options); }
  catch { findings = [issue('FILE', 'Catalog validation could not read its working files.')]; }
  stdout.write(options.json ? `${JSON.stringify(findings)}\n` : findings.length
    ? findings.map(f => `${f.code} ${f.path || '/'}: ${f.message}\n`).join('') : 'Catalog validation passed.\n');
  return findings.length ? 1 : 0;
}
