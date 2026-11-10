import { readFileSync, existsSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';

export function catalogSchema(name) {
  const source = new URL(`../../schemas/${name}.schema.json`, import.meta.url);
  const packaged = new URL(`../schemas/${name}.schema.json`, import.meta.url);
  return JSON.parse(readFileSync(existsSync(source) ? source : packaged, 'utf8'));
}

// Match the catalog contract tests without introducing a formats dependency.
export function catalogAjv(options = {}) {
  const ajv = new Ajv2020({ strict: true, allowUnionTypes: true, allErrors: true, ...options });
  const validDate = value => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const date = new Date(`${value}T00:00:00Z`);
    return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 10) === value;
  };
  ajv.addFormat('date', validDate);
  ajv.addFormat('date-time', value => {
    const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
    return Boolean(m && validDate(m[1]) && +m[2] < 24 && +m[3] < 60 && +m[4] < 60 && +(m[5] ?? 0) < 24 && +(m[6] ?? 0) < 60);
  });
  ajv.addFormat('uri', value => { try { return Boolean(new URL(value).hostname); } catch { return false; } });
  ajv.addFormat('email', /^[^\s@]+@[^\s@]+\.[^\s@]+$/);
  for (const name of ['ihapp-catalog', 'ihapp-catalog-index']) {
    ajv.addSchema(catalogSchema(name));
  }
  return ajv;
}
