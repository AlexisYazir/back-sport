import { BadRequestException } from '@nestjs/common';

const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;
const BACKUP_TYPES = new Set(['full', 'critical']);

function segments(value: unknown): string[] | null {
  if (typeof value !== 'string' || value.length > 1024 || /\s/.test(value))
    return null;
  const parts = value.split('/');
  return parts.every((part) => SEGMENT.test(part)) ? parts : null;
}

export function isBackupObjectKey(
  value: unknown,
  extension?: 'dump' | 'log',
): value is string {
  const parts = segments(value);
  return !!(
    parts &&
    parts.length === 3 &&
    BACKUP_TYPES.has(parts[0]) &&
    (extension
      ? parts[2].endsWith('.' + extension)
      : /\.(?:dump|log)$/.test(parts[2]))
  );
}

export function assertBackupObjectKey(
  value: unknown,
  extension: 'dump' | 'log',
): asserts value is string {
  if (!isBackupObjectKey(value, extension)) {
    throw new BadRequestException('Clave de respaldo no válida');
  }
}

export function assertBackupFolderKey(value: unknown): asserts value is string {
  const parts = segments(value);
  if (!parts || parts.length !== 2 || !BACKUP_TYPES.has(parts[0])) {
    throw new BadRequestException('Carpeta de respaldo no válida');
  }
}

export function isMaintenanceLogKey(value: unknown): value is string {
  const parts = segments(value);
  return !!(
    parts &&
    parts.length === 3 &&
    parts[0] === 'logsVacum' &&
    parts[2].endsWith('.log')
  );
}

/** This legacy storage adapter never exposes any other application namespace. */
export function isLegacyStorageObjectKey(value: unknown): value is string {
  if (isBackupObjectKey(value) || isMaintenanceLogKey(value)) return true;
  const parts = segments(value);
  return !!(
    parts &&
    parts.length === 3 &&
    parts[0] === 'logs' &&
    parts[2].endsWith('.log')
  );
}

export function assertLegacyStorageObjectKey(
  value: unknown,
): asserts value is string {
  if (!isLegacyStorageObjectKey(value)) {
    throw new BadRequestException('Clave de almacenamiento no válida');
  }
}

export function assertLegacyStoragePrefix(
  value: unknown,
): asserts value is string {
  const parts =
    typeof value === 'string' && value.endsWith('/')
      ? segments(value.slice(0, -1))
      : null;
  if (
    !parts ||
    parts.length > 2 ||
    !['full', 'critical', 'logs', 'logsVacum'].includes(parts[0])
  ) {
    throw new BadRequestException('Prefijo de almacenamiento no válido');
  }
}
