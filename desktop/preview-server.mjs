import http from 'node:http';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveInside } from '../src/util.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), 'renderer');
const port = Number.parseInt(process.env.AEGIS_PREVIEW_PORT ?? '4173', 10);
const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.svg', 'image/svg+xml']
]);

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    const relative = decodeURIComponent(url.pathname === '/' ? 'index.html' : url.pathname.slice(1));
    const file = resolveInside(root, relative);
    const stat = await fsp.stat(file);
    if (!stat.isFile()) throw Object.assign(new Error('Not found'), { code: 'ENOENT' });
    response.writeHead(200, {
      'Content-Type': contentTypes.get(path.extname(file)) ?? 'application/octet-stream',
      'Cache-Control': 'no-store',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    });
    response.end(await fsp.readFile(file));
  } catch (error) {
    response.writeHead(error.code === 'ENOENT' ? 404 : 400, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end(error.code === 'ENOENT' ? 'Not found' : 'Bad request');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Aegis UI preview: http://127.0.0.1:${port}/?preview=1`);
});
