/**
 * Shared types of registry enrichment (REQ-004; contract
 * `docs/contracts/REQ-004-notice-and-outputs.md` section 4, migration 006).
 * Type-only module.
 */
import type { DigestAlgorithm } from './integrity';

/** `scan_dependencies.license_enrichment_status` (migration 006 CHECK, contract section 4). */
export type EnrichmentStatus =
  | 'ok'
  | 'no_license'
  | 'not_found'
  | 'unreachable'
  | 'error'
  | 'disabled'
  | 'version_unknown'
  | 'invalid_coordinates'
  | 'budget_exceeded';

/** `scan_dependencies.license_source` (migration 006 CHECK). */
export type LicenseSource = 'registry:npm' | 'registry:pypi' | 'lockfile (unverified)' | 'none';

/** `scan_dependencies.notice_status` (migration 006 CHECK). */
export type NoticeStatus =
  | 'collected'
  | 'no_license_file'
  | 'unsupported_format'
  | 'limit_exceeded'
  | 'no_candidate'
  | 'integrity_failed'
  | 'download_failed'
  | 'processing_failed'
  | 'budget_exceeded'
  | 'not_attempted'
  | 'not_runtime';

/** One downloadable archive of a package version (stored in `registry_package_cache.archive_candidates`). */
export interface ArchiveCandidate {
  url: string;
  algorithm: DigestAlgorithm;
  /** Accepted digests in the normalized encoding (sha512 base64; sha1/sha256 lower-case hex). */
  digests: string[];
  /** Declared size in bytes, null when unknown. */
  size: number | null;
  filename: string | null;
}

/** Metadata extracted from a found registry document (AC-P14-1/2/3). */
export interface RegistryMetadata {
  /** Derived license declaration; null = the registry has no license. */
  declaredLicense: string | null;
  /** Long PyPI license text (NOTICE fallback), null otherwise. */
  licenseText: string | null;
  archiveCandidates: ArchiveCandidate[];
}

/** Outcome of one metadata lookup (cache or network). */
export type MetadataOutcome =
  | { kind: 'found'; metadata: RegistryMetadata }
  | { kind: 'not_found' }
  | { kind: 'unreachable'; code: string }
  | { kind: 'error'; code: string };
