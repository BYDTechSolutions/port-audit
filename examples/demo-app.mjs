// A small app with typical misconfigurations, to try port-audit on:
//
//   node examples/demo-app.mjs          # listens on http://localhost:3000/
//   npx @bydtech/port-audit --port 3000
//
// It imitates an Express app without helmet: no security headers, X-Powered-By,
// a session cookie without HttpOnly, CORS that reflects any origin with
// credentials, an old jQuery from a CDN without integrity, and a bundled lodash
// with known advisories. Node built-ins only; it listens on 127.0.0.1.
import { createServer } from 'node:http';

const port = Number(process.env.PORT ?? 3000);

const page = `<!doctype html>
<html><head><title>Demo shop</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@3.3.7/dist/css/bootstrap.min.css">
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="/js/vendor.js"></script>
</head><body><h1>Demo shop</h1></body></html>`;

// What a bundler leaves at the top of a lodash build: the license banner and the version constant.
const vendor = `/** @license Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE */
;(function(){var VERSION="4.17.15";/* ... */})();`;

createServer((req, res) => {
  res.setHeader('X-Powered-By', 'Express');
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  if (req.url === '/js/vendor.js') {
    res.setHeader('Content-Type', 'application/javascript');
    res.end(vendor);
    return;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.statusCode = 404;
    res.end(`Cannot ${req.method} ${req.url}`);
    return;
  }
  res.setHeader('Set-Cookie', 'connect.sid=s%3Ademo-session-value.abc123; Path=/');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(page);
}).listen(port, '127.0.0.1', () => {
  console.log(`Demo app on http://localhost:${port}/ (Ctrl+C to stop)`);
});
