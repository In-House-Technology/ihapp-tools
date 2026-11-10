// Proposed catalog format (LAB-159). Pure helpers only; no deploy/check integration.
import { createHash } from 'node:crypto';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (o, k) => Object.hasOwn(o, k);
const money = /^-?\d+(\.\d{1,2})?$/;
const email = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const scalarTypes = new Set(['string', 'text', 'integer', 'number', 'boolean', 'enum', 'email', 'group', 'money']);
const clone = v => structuredClone(v);
const pointer = s => String(s).replaceAll('~', '~0').replaceAll('/', '~1');
const at = (path, key) => `${path}/${pointer(key)}`;
const finding = (code, message, path) => ({ code: `IHC-CATALOG-${code}`, message, path });

// Tables and direct egress cannot be inferred from company-app.yaml. The caller
// supplies those declarations separately; reasons never enter the derived object.
export function permissionsOf(companyApp, declared = {}) {
  const mcp = companyApp.mcp;
  const tools = !mcp || mcp.enabled === false ? [] : Array.isArray(mcp.tools)
    ? mcp.tools : Object.entries(mcp.tools ?? {}).map(([name, spec]) => ({ ...spec, name }));
  return {
    data: {
      database: companyApp.database?.required === true,
      redis: companyApp.dependencies?.redis?.required === true,
      object_storage: companyApp.object_storage?.required === true,
      tables: clone(declared.data?.tables ?? []),
    },
    // Forward-auth and actor JWTs expose email and groups. Conservatively declare
    // both available, rather than claiming we can infer whether code reads them.
    identity: { email: true, groups: true },
    connectors: Object.entries(companyApp.secrets_proxy ?? {}).map(([service, rule]) => ({
      service, methods: [...rule.methods], paths: [...rule.path_prefixes],
    })),
    mcp_tools: tools.map(t => ({ name: t.name, access: t.access === 'read' ? 'read' : 'write',
      ...(t.groups ? { groups: [...t.groups] } : {}) })),
    egress: (declared.egress ?? []).map(({ host }) => ({ host })),
  };
}

// Sort recursively, emitting keys directly: JSON.stringify(object) would reorder
// integer-looking keys numerically, contrary to the canonical lexical order.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  const json = JSON.stringify(value);
  if (json === undefined || (typeof value === 'number' && !Number.isFinite(value))) throw new TypeError('Expected a JSON value');
  return json;
}
export function permissionsDigest(permissions) {
  return `sha256:${createHash('sha256').update(canonical(permissions), 'utf8').digest('hex')}`;
}

// Same exact-or-slash-descendant semantics as the credential proxy. A trailing
// slash grants descendants only, and cannot cover the bare parent path.
function covers(prefix, path) {
  return prefix === '/' || prefix === path || (prefix.endsWith('/')
    ? path.startsWith(prefix) : path.startsWith(`${prefix}/`));
}

export function permissionsWidened(approved, next) {
  const out = [];
  const add = (kind, detail) => out.push({ kind, detail });
  for (const key of ['database', 'redis', 'object_storage']) {
    if (next.data[key] && !approved.data[key]) add('storage', key);
  }
  for (const table of new Set(next.data.tables)) {
    if (!approved.data.tables.includes(table)) add('table', table);
  }
  for (const key of ['email', 'groups']) {
    if (next.identity[key] && !approved.identity[key]) add('identity', key);
  }
  for (const rule of next.connectors) {
    const old = approved.connectors.filter(c => c.service === rule.service);
    if (!old.length) { add('connector', rule.service); continue; }
    for (const method of new Set(rule.methods)) {
      const grants = old.filter(c => c.methods.includes(method));
      if (!grants.length) add('method', `${rule.service} ${method}`);
      else for (const path of new Set(rule.paths)) {
        if (!grants.some(c => c.paths.some(p => covers(p, path)))) add('path', `${rule.service} ${method} ${path}`);
      }
    }
  }
  for (const tool of next.mcp_tools) {
    const old = approved.mcp_tools.find(t => t.name === tool.name);
    if (!old) { add('tool', tool.name); continue; }
    if (old.access === 'read' && tool.access === 'write') add('tool-access', tool.name);
    // Missing/empty groups means no per-tool restriction (scopes still apply).
    if (old.groups?.length) {
      if (!tool.groups?.length) add('tool-groups', `${tool.name}: unrestricted`);
      else for (const group of new Set(tool.groups)) {
        if (!old.groups.includes(group)) add('tool-groups', `${tool.name}: ${group}`);
      }
    }
  }
  for (const { host } of next.egress) {
    if (!approved.egress.some(e => e.host.toLowerCase() === host.toLowerCase())) add('egress', host);
  }
  return out;
}

function validateValue(spec, value, path, out) {
  const add = (code, message, where = path) => out.push(finding(code, message, where));
  let valid;
  switch (spec.type) {
    case 'string': case 'text': valid = typeof value === 'string'; break;
    case 'group': valid = typeof value === 'string' && value.length > 0; break;
    case 'email': valid = typeof value === 'string' && email.test(value); break;
    case 'money': valid = typeof value === 'string' && money.test(value); break;
    case 'integer': valid = Number.isInteger(value); break;
    case 'number': valid = typeof value === 'number' && Number.isFinite(value); break;
    case 'boolean': valid = typeof value === 'boolean'; break;
    case 'enum': valid = typeof value === 'string' && spec.options?.some(o => o.value === value); break;
    case 'object': valid = object(value); break;
    case 'list': valid = Array.isArray(value); break;
    default: valid = false;
  }
  if (!valid) { add('CONFIG-TYPE', `Expected ${spec.type}.`); return; }
  if (spec.type === 'string') {
    if ([...value].length > (spec.max_length ?? Infinity)) add('CONFIG-CONSTRAINT', 'String exceeds max_length.');
    if (spec.pattern) {
      try { if (!new RegExp(spec.pattern, 'u').test(value)) add('CONFIG-CONSTRAINT', 'String does not match pattern.'); }
      catch { add('CONFIG-SPEC', 'Invalid string pattern.'); }
    }
  }
  if (['integer', 'number'].includes(spec.type) && (value < (spec.minimum ?? -Infinity) || value > (spec.maximum ?? Infinity))) {
    add('CONFIG-CONSTRAINT', 'Number is outside minimum/maximum.');
  }
  if (spec.type === 'list') {
    if (value.length < (spec.min_items ?? 0) || value.length > (spec.max_items ?? Infinity)) add('CONFIG-CONSTRAINT', 'List is outside min_items/max_items.');
    if (!spec.items) { add('CONFIG-SPEC', 'List needs items.'); return; }
    value.forEach((v, i) => validateValue(spec.items, v, at(path, i), out));
  }
  if (spec.type === 'object') validatePoints(spec.fields ?? [], value, path, out);
}

function validatePoints(points, values, path, out) {
  for (const key of Object.keys(values)) {
    if (!points.some(p => p.key === key)) out.push(finding('CONFIG-UNKNOWN', 'Unknown configuration key.', at(path, key)));
  }
  for (const point of points) {
    const where = at(path, point.key);
    if (own(values, point.key)) validateValue(point, values[point.key], where, out);
    else if (own(point, 'default')) validateValue(point, point.default, where, out);
    else if (point.required === true) out.push(finding('CONFIG-REQUIRED', 'Required configuration value is missing.', where));
  }
}

export function validateConfig(points, values) {
  const out = [];
  if (!object(values)) return [finding('CONFIG-TYPE', 'Expected a configuration object.', '')];
  validatePoints(points, values, '', out);
  return out;
}

function effectiveValue(spec, value) {
  if (spec.type === 'list') return value.map(v => effectiveValue(spec.items, v));
  if (spec.type === 'object') return effectiveConfig(spec.fields, value);
  return clone(value);
}
// Call after schema/semantic validation and validateConfig. Unknown keys are not
// propagated; missing required values remain absent and are reported by validation.
export function effectiveConfig(points, values) {
  return Object.fromEntries(points.filter(p => own(values, p.key) || own(p, 'default')).map(p =>
    [p.key, effectiveValue(p, own(values, p.key) ? values[p.key] : p.default)]));
}

export function validateCatalogManifest(manifest) {
  // Complements JSON Schema; it does not replace structural validation.
  const out = [];
  const add = (code, message, path) => out.push(finding(code, message, path));
  const unique = (items, key, path, code) => {
    const seen = new Set();
    items.forEach((item, i) => {
      if (seen.has(item[key])) add(code, `Duplicate ${key}: ${item[key]}.`, at(at(path, i), key));
      seen.add(item[key]);
    });
  };
  const checkPoints = (points, path) => {
    unique(points, 'key', path, 'CONFIG-KEY');
    points.forEach((p, i) => {
      const where = at(path, i);
      if (!own(p, 'default') && p.required !== true) add('CONFIG-DEFAULT', 'Provide default unless required is true.', at(where, 'default'));
      checkSpec(p, where);
    });
  };
  const checkSpec = (spec, path) => {
    if (!scalarTypes.has(spec.type) && spec.type !== 'list' && spec.type !== 'object') add('CONFIG-SPEC', 'Unknown config type.', at(path, 'type'));
    if (spec.minimum > spec.maximum || spec.min_items > spec.max_items) add('CONFIG-SPEC', 'Minimum exceeds maximum.', path);
    if (spec.pattern !== undefined) {
      try { new RegExp(spec.pattern, 'u'); } catch { add('CONFIG-SPEC', 'Invalid string pattern.', at(path, 'pattern')); }
    }
    if (spec.options) unique(spec.options, 'value', at(path, 'options'), 'CONFIG-SPEC');
    if (spec.type === 'list' && spec.items) {
      if (!scalarTypes.has(spec.items.type) && spec.items.type !== 'object') add('CONFIG-SPEC', 'List items must be scalar or a flat object.', at(path, 'items'));
      checkSpec(spec.items, at(path, 'items'));
    }
    if (spec.type === 'object') checkPoints(spec.fields ?? [], at(path, 'fields'));
    if (own(spec, 'default')) validateValue(spec, spec.default, at(path, 'default'), out);
  };
  checkPoints(manifest.config ?? [], '/config');
  const releases = manifest.releases ?? [];
  if (releases[0]?.version !== manifest.version) add('RELEASE-HEAD', 'First release version must equal manifest version.', '/releases/0/version');
  unique(releases, 'version', '/releases', 'RELEASE-UNIQUE');
  const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
  const compare = (a, b) => {
    const aa = a.split('.').map(BigInt), bb = b.split('.').map(BigInt);
    for (let i = 0; i < 3; i++) { if (aa[i] !== bb[i]) return aa[i] > bb[i] ? 1 : -1; }
    return 0;
  };
  releases.forEach((r, i) => {
    if (i && semver.test(r.version) && semver.test(releases[i - 1].version) && compare(releases[i - 1].version, r.version) < 0) {
      add('RELEASE-ORDER', 'Releases must be newest first by semantic version.', `/releases/${i}/version`);
    }
  });
  const permissions = manifest.permissions;
  if (permissions) {
    unique(permissions.connectors ?? [], 'service', '/permissions/connectors', 'PERMISSION-UNIQUE');
    unique(permissions.mcp_tools ?? [], 'name', '/permissions/mcp_tools', 'PERMISSION-UNIQUE');
    unique((permissions.egress ?? []).map(e => ({ host: e.host.toLowerCase() })), 'host', '/permissions/egress', 'PERMISSION-UNIQUE');
  }
  return out;
}
