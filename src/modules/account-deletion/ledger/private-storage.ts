import { execFile } from 'node:child_process';
import { lstat } from 'node:fs/promises';
import { promisify } from 'node:util';
import { DeletionLedgerError } from './deletion-ledger';

const execute = promisify(execFile);

/** An application-provided verifier must enforce equivalent OS access controls. */
export type PrivateStorageVerifier = (
  path: string,
  kind: 'directory' | 'file',
) => Promise<void>;

export const assertPrivateStorage: PrivateStorageVerifier = async (
  path,
  kind,
) => {
  const stat = await lstat(path);
  if (
    stat.isSymbolicLink() ||
    (kind === 'directory' ? !stat.isDirectory() : !stat.isFile()) ||
    (kind === 'file' && stat.nlink !== 1)
  ) {
    throw new DeletionLedgerError('UNSAFE_STORAGE');
  }
  if (process.platform !== 'win32') {
    if (
      typeof process.getuid !== 'function' ||
      stat.uid !== process.getuid() ||
      (stat.mode & 0o077) !== 0
    ) {
      throw new DeletionLedgerError('UNSAFE_STORAGE');
    }
    return;
  }

  // chmod/mode is not an ACL check on Windows. Read the native DACL instead.
  // Only this identity, SYSTEM and local administrators may have Allow entries.
  const literal = path.replace(/'/g, "''");
  const script = `
$ErrorActionPreference='Stop'
$acl=Get-Acl -LiteralPath '${literal}'
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed=@($me,'S-1-5-18','S-1-5-32-544')
$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
if ($allowed -notcontains $owner) { exit 11 }
$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if ($rules.Count -eq 0) { exit 13 }
foreach ($rule in $rules) {
  if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $allowed -notcontains $rule.IdentityReference.Value) { exit 12 }
}
Write-Output 'PRIVATE_STORAGE_OK'
`;
  try {
    const result = await execute(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-EncodedCommand',
        Buffer.from(script, 'utf16le').toString('base64'),
      ],
      { windowsHide: true, timeout: 5000, maxBuffer: 2048 },
    );
    if (result.stdout.trim() !== 'PRIVATE_STORAGE_OK') {
      throw new DeletionLedgerError('UNSAFE_STORAGE');
    }
  } catch {
    throw new DeletionLedgerError('UNSAFE_STORAGE');
  }
};
