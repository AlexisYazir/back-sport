interface LogRequest {
  method?: unknown;
  route?: unknown;
}

export function requestLogMetadata(request: LogRequest): {
  method: string;
  path: string;
} {
  const method =
    typeof request.method === 'string' ? request.method.toUpperCase() : '';
  const route: unknown = request.route;
  const path: unknown =
    typeof route === 'object' && route !== null && 'path' in route
      ? route.path
      : undefined;
  return {
    method: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
      'OPTIONS',
      'HEAD',
    ].includes(method)
      ? method
      : 'OTHER',
    // Express assigns this template from the server's route registration.
    // Never fall back to originalUrl/path/baseUrl, which may contain credentials.
    path:
      typeof path === 'string' &&
      path.startsWith('/') &&
      path.length <= 256 &&
      !/[\r\n?#]/.test(path)
        ? path
        : '[unmatched]',
  };
}
