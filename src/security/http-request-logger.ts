import morgan from 'morgan';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { requestLogMetadata } from './request-log-metadata';

morgan.token('safe-method', (req) => requestLogMetadata(req).method);
morgan.token('safe-route', (req) => requestLogMetadata(req).path);
morgan.token('date-mx', () =>
  new Intl.DateTimeFormat('en-GB', {
    timeZone: 'America/Mexico_City',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
    .format(new Date())
    .replace(',', ''),
);

export function createHttpRequestLogger(
  options: morgan.Options<IncomingMessage, ServerResponse> = {},
) {
  return morgan(
    ':remote-addr - - [:date-mx] ":safe-method :safe-route HTTP/:http-version" :status :res[content-length]',
    options,
  );
}
