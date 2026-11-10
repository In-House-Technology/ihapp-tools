import { createHash } from 'node:crypto';

// SHA-256 of the complete, whitespace-normalized license terms. Attribution
// names and years are outside the terms. Comparing complete bodies avoids
// accepting an SPDX label, a few keywords, or a modified permission grant.
const bodies = {
  MIT: 'fe2a9817987f862eaced948f0468c7f51d2fedfc48c5c505b246a49a3870e9a5',
  'MIT-0': '6c0fe4001061a2cc11528179f3e52bd7d864efdbc714965aef4b7c61aecb4adc',
  'Apache-2.0': 'b316b715c7f48af32f6265b3de80b9656fdbddc57f5854215c8a4c6e0ad42c05',
  'AGPL-3.0-only': '78832c70553881221c41c9a1f1f1a2a88faaa6a6d2e198c700b8ede5a0976854',
};
const hash = text => createHash('sha256').update(text).digest('hex');

export function detectLicense(text) {
  const normalized = text.replace(/\s+/g, ' ').trim();
  const permission = normalized.indexOf('Permission is hereby granted,');
  if (permission >= 0) {
    const digest = hash(normalized.slice(permission));
    for (const id of ['MIT', 'MIT-0']) if (digest === bodies[id]) return id;
  }
  const end = normalized.indexOf('END OF TERMS AND CONDITIONS');
  if (end < 0) return;
  const through = end + 'END OF TERMS AND CONDITIONS'.length;
  const apache = normalized.indexOf('TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION');
  if (apache >= 0 && hash(normalized.slice(apache, through)) === bodies['Apache-2.0']) return 'Apache-2.0';
  const preamble = normalized.indexOf('Preamble');
  if (normalized.includes('GNU AFFERO GENERAL PUBLIC LICENSE Version 3, 19 November 2007') && preamble >= 0 &&
      hash(normalized.slice(preamble, through)) === bodies['AGPL-3.0-only']) return 'AGPL-3.0-only';
}
