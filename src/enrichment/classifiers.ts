/**
 * PyPI trove license classifiers -> SPDX ids (REQ-004 AC-P14-3, D-78;
 * ADR-006 Karar 1). Pure module (no imports).
 *
 * Only classifiers that name one license version are mapped. Version-less
 * ones (`OSI Approved :: BSD License`, `GNU General Public License (GPL)`,
 * `GNU Library or Lesser General Public License (LGPL)`, `Artistic License`,
 * `Public Domain`, …) are deliberately absent: their last segment goes to the
 * normalizer as raw text and today's alias behaviour applies.
 *
 * Exception: `OSI Approved :: Apache Software License` and `OSI Approved ::
 * Python Software Foundation License` carry no version, but there is no
 * versioned trove classifier for either license and they are used for
 * Apache-2.0 / PSF-2.0 in practice; AC-P14-3 requires Apache 2.0 and PSF
 * coverage, so they are mapped.
 *
 * Changing this table changes the extracted metadata: bump
 * `METADATA_EXTRACTOR_VERSION` (src/enrichment/cache.ts, ADR-006 Karar 10).
 */

const PREFIX = 'License :: ';

/** Classifier path after `License :: ` -> SPDX id (keys compared exactly after whitespace trimming). */
export const TROVE_CLASSIFIER_MAP: Readonly<Record<string, string>> = Object.freeze({
  'OSI Approved :: MIT License': 'MIT',
  'OSI Approved :: MIT No Attribution License (MIT-0)': 'MIT-0',
  'OSI Approved :: Apache Software License': 'Apache-2.0',
  'OSI Approved :: ISC License (ISCL)': 'ISC',
  'OSI Approved :: Python Software Foundation License': 'PSF-2.0',
  'OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)': 'MPL-2.0',
  'OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)': 'MPL-1.1',
  'OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)': 'LGPL-2.0-only',
  'OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)': 'LGPL-2.0-or-later',
  'OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)': 'LGPL-3.0-only',
  'OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)': 'LGPL-3.0-or-later',
  'OSI Approved :: GNU General Public License v2 (GPLv2)': 'GPL-2.0-only',
  'OSI Approved :: GNU General Public License v2 or later (GPLv2+)': 'GPL-2.0-or-later',
  'OSI Approved :: GNU General Public License v3 (GPLv3)': 'GPL-3.0-only',
  'OSI Approved :: GNU General Public License v3 or later (GPLv3+)': 'GPL-3.0-or-later',
  'OSI Approved :: GNU Affero General Public License v3': 'AGPL-3.0-only',
  'OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)': 'AGPL-3.0-or-later',
  'OSI Approved :: The Unlicense (Unlicense)': 'Unlicense',
  'CC0 1.0 Universal (CC0 1.0) Public Domain Dedication': 'CC0-1.0',
  'OSI Approved :: zlib/libpng License': 'Zlib',
  'OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)': 'EPL-2.0',
  'OSI Approved :: Eclipse Public License 1.0 (EPL-1.0)': 'EPL-1.0',
  'OSI Approved :: European Union Public Licence 1.2 (EUPL 1.2)': 'EUPL-1.2',
  'OSI Approved :: European Union Public Licence 1.1 (EUPL 1.1)': 'EUPL-1.1',
  'OSI Approved :: Boost Software License 1.0 (BSL-1.0)': 'Boost-1.0',
  'OSI Approved :: Historical Permission Notice and Disclaimer (HPND)': 'HPND',
  'OSI Approved :: Artistic License 2.0': 'Artistic-2.0',
  'OSI Approved :: BSD Zero Clause License (0BSD)': '0BSD',
});

/** Classifiers that carry no license name and are ignored (AC-P14-3). */
const NAMELESS: ReadonlySet<string> = new Set(['OSI Approved', 'DFSG approved', 'Free For Educational Use', 'Free For Home Use', 'Free for non-commercial use', 'Freely Distributable', 'Freeware', 'Other/Proprietary License']);

/** One classifier interpreted: a mapped SPDX id, the raw last segment for the normalizer, or nothing. */
export type ClassifierTerm = { kind: 'spdx'; id: string } | { kind: 'raw'; text: string };

/**
 * Interprets one trove classifier. Returns null for non-license classifiers
 * and for license classifiers without a license name.
 */
export function classifierTerm(classifier: string): ClassifierTerm | null {
  if (typeof classifier !== 'string') return null;
  const trimmed = classifier.trim();
  if (!trimmed.startsWith(PREFIX)) return null;
  const rest = trimmed
    .slice(PREFIX.length)
    .split('::')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .join(' :: ');
  if (rest.length === 0 || NAMELESS.has(rest)) return null;
  const mapped = TROVE_CLASSIFIER_MAP[rest];
  if (mapped !== undefined) return { kind: 'spdx', id: mapped };
  const sep = rest.lastIndexOf(' :: ');
  const last = sep === -1 ? rest : rest.slice(sep + 4);
  if (NAMELESS.has(last)) return null;
  return { kind: 'raw', text: last };
}
