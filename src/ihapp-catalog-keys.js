import { createHash, createPublicKey, verify } from 'node:crypto';
import { catalogAjv, catalogSchema } from './ihapp-catalog-schema.js';
import { IhappError } from './ihapp-files.js';

// InHouse catalog signing key (generated 2026-11-10; the private key lives only in the
// catalog repo's catalog-signing environment). Rotation: add the new entry first,
// remove the old one after every index is signed with the new key.
const INHOUSE_2026_11_PUBLIC_KEY = 'RCG+TSDsf7kptiulx+4b3CuHReDQnUOo+RoQgsxkr4o=';
export const PINNED_CATALOG_KEYS = Object.freeze([
  Object.freeze({ key_id: 'inhouse-2026-11', alg: 'ed25519', public_key: INHOUSE_2026_11_PUBLIC_KEY }),
]);

const ajv = catalogAjv();
const validSignature = ajv.compile(catalogSchema('ihapp-catalog-signature'));
const validKeys = ajv.compile(catalogSchema('ihapp-catalog-keys'));
const fail = () => { throw new IhappError('IHC-CATALOG-SIGNATURE', 'The catalog index requires a valid signature from a trusted catalog key.'); };

// Buffer.from alone accepts malformed base64. Require the canonical encoding.
export function decodeCatalogRaw(raw) {
  if (typeof raw !== 'string' || !raw.length) fail();
  const bytes = Buffer.from(raw, 'base64');
  if (bytes.toString('base64') !== raw) fail();
  return bytes;
}

export function verifyCatalogSignature(raw, signature, keys = PINNED_CATALOG_KEYS) {
  try {
    if (typeof keys === 'string') keys = JSON.parse(keys);
    if (!Buffer.isBuffer(raw) || !validSignature(signature) || !validKeys(keys)) fail();
    if (new Set(keys.map(key => key.key_id)).size !== keys.length) fail();
    const key = keys.find(key => key.key_id === signature.key_id);
    if (!key || createHash('sha256').update(raw).digest('hex') !== signature.sha256) fail();
    const publicKey = createPublicKey({ format: 'jwk', key: {
      kty: 'OKP', crv: 'Ed25519', x: Buffer.from(key.public_key, 'base64').toString('base64url'),
    } });
    if (!verify(null, raw, publicKey, Buffer.from(signature.signature, 'base64'))) fail();
    return true;
  } catch { fail(); }
}
