import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' };
const server = createServer(async (req, res) => {
  const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (pathname === '/healthz') { res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }).end('ok'); return; }
  const resourceFiles = {
    '/resources/password-rules.json': 'password-rules.json',
    '/resources/change-password-URLs.json': 'change-password-URLs.json'
  };
  if (resourceFiles[pathname]) {
    try {
      const data = await readFile(join(root, 'resources', resourceFiles[pathname]));
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=3600', 'X-Resource-Source': 'bundled-apple-data' });
      res.end(data);
    } catch { res.writeHead(503).end('Bundled Apple resource unavailable'); }
    return;
  }
  const relative = pathname === '/' ? 'index.html' : normalize(pathname).replace(/^([/\\])+/, '');
  const file = join(root, relative);
  if (!file.startsWith(root)) { res.writeHead(403).end('Forbidden'); return; }
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' });
    res.end(body);
  } catch {
    res.writeHead(404).end('Not found');
  }
});
server.listen(Number(process.env.PORT || 4173), '0.0.0.0', () => console.log(`KeyNest listening on port ${process.env.PORT || 4173}`));
