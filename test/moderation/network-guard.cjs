'use strict';
// Loaded before the QA application: no TCP connection outside numeric loopback.
// Provider credentials are also excluded by the runner. This is a QA guard,
// not a replacement for an operating-system sandbox.
const net = require('node:net');
const originalConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const options = Array.isArray(args[0]) ? args[0][0] : typeof args[0] === 'object' && args[0] !== null
    ? args[0]
    : { port: args[0], host: typeof args[1] === 'string' ? args[1] : undefined };
  if (
    options.path ||
    !['127.0.0.1', '::1'].includes(options.host) ||
    !Number.isInteger(Number(options.port)) ||
    Number(options.port) < 1024 || Number(options.port) > 65535
  ) {
    throw new Error('MODERATION_QA_NON_LOOPBACK_CONNECTION_FORBIDDEN');
  }
  return originalConnect.apply(this, args);
};
