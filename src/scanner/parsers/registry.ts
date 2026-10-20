/**
 * Ecosystem -> parser registry (REQ-011 D-304, D-315).
 *
 * One entry per `SCAN_ECOSYSTEMS` value (the `Record` type makes a missing
 * ecosystem a compile error). The npm/PyPI/.NET parsers keep their F4/F5
 * signatures; the REQ-011 ecosystems run through the parser kit with a fresh
 * `ParserContext` per ecosystem and a scan budget shared by all of them
 * (AC-P40-5).
 */
import type { ScanEcosystem } from '../../types/scan';
import type { ParseResult, TreeWalk } from './common';
import { parseDart } from './dart';
import { parseGo } from './golang';
import { parseJava } from './java';
import { KitScanBudget, ParserContext, type KitEcosystem, type KitParser } from './kit';
import type { IntegrityCollector } from './lockIntegrityValue';
import { parse as parseNodejs } from './nodejs';
import { parse as parseNuget } from './nuget';
import { parsePhp } from './php';
import { parse as parsePython } from './python';
import { parseRuby } from './ruby';
import { parseRust } from './rust';
import { parseSwift } from './swift';

export interface ParserRunContext {
  /** L-5 side channel of the npm/NuGet lock parsers (REQ-005, ADR-007 Karar 12); not part of the result. */
  integrityCollector?: IntegrityCollector;
  /** Scan-wide record budget of the kit parsers (one per `parseManifests` call). */
  budget: KitScanBudget;
}

export type EcosystemParser = (walk: TreeWalk, run: ParserRunContext) => ParseResult;

/** Kit parser of each REQ-011 ecosystem. */
export const KIT_PARSERS: Readonly<Record<KitEcosystem, KitParser>> = Object.freeze({
  java: parseJava,
  go: parseGo,
  php: parsePhp,
  rust: parseRust,
  ruby: parseRuby,
  dart: parseDart,
  swift: parseSwift,
});

function kit(ecosystem: KitEcosystem): EcosystemParser {
  return (walk, run) => KIT_PARSERS[ecosystem](walk, new ParserContext(walk, ecosystem, run.budget));
}

export const PARSER_REGISTRY: Readonly<Record<ScanEcosystem, EcosystemParser>> = Object.freeze({
  nodejs: (walk, run) => parseNodejs(walk, run.integrityCollector),
  python: (walk) => parsePython(walk),
  dotnet: (walk, run) => parseNuget(walk, run.integrityCollector),
  java: kit('java'),
  go: kit('go'),
  php: kit('php'),
  rust: kit('rust'),
  ruby: kit('ruby'),
  dart: kit('dart'),
  swift: kit('swift'),
});

/** Parser of `ecosystem`, or undefined for an unsupported value (own keys only). */
export function parserFor(ecosystem: string): EcosystemParser | undefined {
  return Object.prototype.hasOwnProperty.call(PARSER_REGISTRY, ecosystem) ? PARSER_REGISTRY[ecosystem as ScanEcosystem] : undefined;
}
