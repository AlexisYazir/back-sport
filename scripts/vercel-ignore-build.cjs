'use strict';

const { execFileSync } = require('node:child_process');

// Vercel skips a build on exit 0 and continues it on exit 1.
try {
  const message = execFileSync('git', ['log', '-1', '--format=%B'], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 10000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  process.exitCode = message.includes('[skip vercel]') ? 0 : 1;
} catch {
  console.error('Cannot verify the commit message; deployment remains skipped.');
  process.exitCode = 0;
}
