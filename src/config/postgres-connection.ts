import { isIP } from 'node:net';
import { checkServerIdentity } from 'node:tls';
import type { ConnectionOptions as TlsConnectionOptions } from 'node:tls';
import type { PostgresConnectionOptions } from 'typeorm/driver/postgres/PostgresConnectionOptions';

type ConnectionOptions = Pick<
  PostgresConnectionOptions,
  'host' | 'port' | 'username' | 'password' | 'database' | 'ssl' | 'extra'
>;

function containsControl(value: string, includingSpace = false): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0);
    return code < 32 || code === 127 || (includingSpace && code === 32);
  });
}

/** Parse the URL once; never forward URL TLS parameters to pg. */
export function postgresConnectionOptions(
  connectionUrl: string,
  connectionLimit: number,
  ca?: string,
): ConnectionOptions {
  const invalid = () => new Error('POSTGRES_CONNECTION_CONFIG_INVALID');
  let target: URL;
  let username: string;
  let password: string;
  let database: string;
  try {
    if (
      !connectionUrl ||
      containsControl(connectionUrl, true) ||
      /%(?![\da-f]{2})/i.test(connectionUrl)
    )
      throw invalid();
    target = new URL(connectionUrl);
    username = decodeURIComponent(target.username);
    password = decodeURIComponent(target.password);
    database = decodeURIComponent(target.pathname.slice(1));
  } catch {
    // Never attach URL parser errors: they can contain database credentials.
    throw invalid();
  }

  const host = target.hostname.replace(/^\[|\]$/g, '');
  if (
    !['postgres:', 'postgresql:'].includes(target.protocol) ||
    !host ||
    (!isIP(host) && !/^[a-z\d]+(?:[a-z\d.-]*[a-z\d])?$/i.test(host)) ||
    !username ||
    !password ||
    !database ||
    containsControl(username + password + database) ||
    target.hash ||
    (target.port && (Number(target.port) < 1 || Number(target.port) > 65535))
  )
    throw invalid();

  // Current Neon URLs remain valid, but require always means verified TLS here.
  // Reject duplicate/encoded controls and every other pg URL option rather than
  // allowing pg-connection-string to replace ssl, hostname or credentials.
  const seen = new Set<string>();
  if (/[+%]/.test(target.search)) throw invalid();
  for (const [key, value] of target.searchParams) {
    if (
      seen.has(key) ||
      (key === 'sslmode'
        ? !['require', 'verify-full'].includes(value)
        : key !== 'channel_binding' || value !== 'require')
    )
      throw invalid();
    seen.add(key);
  }
  if (ca !== undefined && !ca.trim()) throw invalid();

  const ssl: Pick<
    TlsConnectionOptions,
    'rejectUnauthorized' | 'checkServerIdentity' | 'ca'
  > = {
    rejectUnauthorized: true,
    // pg sets SNI for DNS hosts. Bind identity verification to the parsed
    // destination as well, including IP destinations without SNI.
    checkServerIdentity: (_servername, certificate) =>
      checkServerIdentity(host, certificate),
    // Omitted by default: Node's trusted roots verify public-CA certificates.
    ...(ca === undefined ? {} : { ca }),
  };
  return {
    host,
    port: target.port ? Number(target.port) : 5432,
    username,
    password,
    database,
    ssl,
    extra: {
      connectionLimit,
      // pg supports SCRAM channel binding when offered by the server; this is
      // independent of the mandatory CA and hostname verification above.
      enableChannelBinding: true,
    },
  };
}
