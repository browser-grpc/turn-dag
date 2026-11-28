// Standalone static server for the browser wallet demo.
//   npm --prefix tests/browser install   (provides vendor deps)
//   node web/server.mjs                  (http://127.0.0.1:8471)
// WebAuthn requires a secure context: http://127.0.0.1 qualifies.
// Vendor modules resolve from tests/browser/node_modules (the same
// install the Playwright suite uses), falling back to web/node_modules.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(webRoot, '..');
const vendorRoots = [
  path.join(repoRoot, 'tests/browser/node_modules'),
  path.join(webRoot, 'node_modules'),
];
const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.css': 'text/css',
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  let filePath;
  if (url.pathname.startsWith('/grpc-vendor/')) {
    const gv = path.join(repoRoot, 'vendor/grpc-dc/js');
    const rel = url.pathname.slice('/grpc-vendor/'.length);
    const fp = path.join(gv, rel);
    if (!fp.startsWith(gv) || !fs.existsSync(fp)) { res.writeHead(404); res.end('not found'); return; }
    res.setHeader('content-type', MIME[path.extname(fp)] || 'application/octet-stream');
    fs.createReadStream(fp).pipe(res);
    return;
  }
  if (url.pathname.startsWith('/vendor/')) {
    const rel = url.pathname.slice('/vendor/'.length);
    filePath = vendorRoots.map((r) => path.join(r, rel)).find((p) => fs.existsSync(p));
    if (!filePath) { res.writeHead(404); res.end('vendor file not found'); return; }
  } else {
    const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    filePath = path.join(webRoot, rel);
    if (!filePath.startsWith(webRoot) || !fs.existsSync(filePath)) {
      res.writeHead(404); res.end('not found'); return;
    }
  }
  res.setHeader('content-type', MIME[path.extname(filePath)] || 'application/octet-stream');
  fs.createReadStream(filePath).pipe(res);
});
server.listen(8471, '127.0.0.1', () => {
  console.log('turn-dag browser wallet at http://localhost:8471 (WebAuthn needs the localhost domain, not the IP)');
});
