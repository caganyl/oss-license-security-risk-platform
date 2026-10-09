/**
 * The only import point of the TOML library (REQ-003 AC-P10-15, ADR-005 Karar 8).
 *
 * `smol-toml@1.9.0` (exact pin) replaces Python's `tomllib`. The text given
 * here is already strictly decoded UTF-8 with the BOM kept; Python's
 * `read_text` universal newlines are applied first (a CR-only file is valid
 * in Python), and a leading BOM is rejected explicitly because `tomllib`
 * rejects it, independent of the library's own behaviour.
 */
import { parse, TomlError } from 'smol-toml';
import { universalNewlines } from './common';

/** TOML syntax error: first line of the library message, at most 200 characters. */
export class TomlSyntaxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TomlSyntaxError';
  }
}

/** Python `tomllib.loads(path.read_text(encoding="utf-8"))` on already decoded text. */
export function parseTomlText(text: string): Record<string, unknown> {
  const normalized = universalNewlines(text);
  if (normalized.startsWith('﻿')) {
    throw new TomlSyntaxError('Geçersiz TOML: dosya UTF-8 BOM ile başlıyor.');
  }
  try {
    return parse(normalized) as Record<string, unknown>;
  } catch (err) {
    if (err instanceof TomlError) {
      const firstLine = (err.message.split(/\r?\n/)[0] ?? '').slice(0, 200);
      throw new TomlSyntaxError(`Geçersiz TOML: ${firstLine}`);
    }
    throw err;
  }
}
