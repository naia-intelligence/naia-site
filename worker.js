const PAGES = [
  { path: '/', name: 'Pocetna' },
  { path: '/o-nama/', name: 'O nama' },
  { path: '/program/', name: 'Program' },
  { path: '/contact/', name: 'Kontakt' },
  { path: '/ritualni-vodic-28-dana-povratka-sebi/', name: 'Ritualni vodic' },
];

function json(data, status, extra) {
  const h = { 'Content-Type': 'application/json' };
  if (extra) Object.assign(h, extra);
  return new Response(JSON.stringify(data), { status: status || 200, headers: h });
}

function norm(path) {
  if (!path || path === '/') return '/';
  let p = path.startsWith('/') ? path : '/' + path;
  if (!p.endsWith('/') && !p.includes('.')) p += '/';
  return p;
}

function toAssetPath(path) {
  if (path === '/') return '/index.html';
  if (path.endsWith('/')) return path + 'index.html';
  return path;
}

async function sign(data, key) {
  const enc = new TextEncoder();
  const ck = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const s = await crypto.subtle.sign('HMAC', ck, enc.encode(data));
  return btoa(String.fromCharCode.apply(null, new Uint8Array(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function makeToken(pw) {
  const payload = btoa(JSON.stringify({ exp: Date.now() + 604800000 })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return payload + '.' + await sign(payload, pw);
}

async function checkToken(token, pw) {
  if (!token || !pw) return false;
  const parts = token.split('.');
  if (!parts[0] || !parts[1]) return false;
  if (parts[1] !== await sign(parts[0], pw)) return false;
  try { return JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'))).exp > Date.now(); } catch { return false; }
}

function getCookie(req) {
  const m = (req.headers.get('Cookie') || '').match(/naia_auth=([^;]+)/);
  return m ? m[1] : null;
}

async function auth(req, env) {
  return checkToken(getCookie(req), env.ADMIN_PASSWORD);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === 'OPTIONS') {
      return new Response(null, { headers: { 'Access-Control-Allow-Origin': url.origin, 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Credentials': 'true' } });
    }

    const cors = { 'Access-Control-Allow-Origin': url.origin, 'Access-Control-Allow-Credentials': 'true' };

    try {
      if (path === '/api/login' && req.method === 'POST') {
        const body = await req.json();
        if (!env.ADMIN_PASSWORD) return json({ error: 'ADMIN_PASSWORD nije postavljen.' }, 500, cors);
        if (body.password !== env.ADMIN_PASSWORD) return json({ error: 'Pogresna lozinka' }, 401, cors);
        const token = await makeToken(env.ADMIN_PASSWORD);
        return json({ success: true }, 200, Object.assign({}, cors, { 'Set-Cookie': 'naia_auth=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800' }));
      }

      if (path === '/api/verify' && req.method === 'GET') {
        return json({ authed: await auth(req, env) }, 200, cors);
      }

      if (path === '/api/pages' && req.method === 'GET') {
        if (!await auth(req, env)) return json({ error: 'Unauthorized' }, 401, cors);
        const pages = [];
        for (const p of PAGES) {
          const kv = await env.CONTENT.get('page:' + p.path);
          pages.push({ path: p.path, name: p.name, edited: !!kv });
        }
        return json({ pages }, 200, cors);
      }

      if (path === '/api/page') {
        if (!await auth(req, env)) return json({ error: 'Unauthorized' }, 401, cors);

        if (req.method === 'GET') {
          const p = url.searchParams.get('path');
          if (!p) return json({ error: 'No path' }, 400, cors);
          const n = norm(p);
          const kv = await env.CONTENT.get('page:' + n);
          if (kv) return json({ html: kv, source: 'kv' }, 200, cors);
          const assetRes = await env.ASSETS.fetch(new Request(new URL(toAssetPath(n), url.origin).toString()));
          if (assetRes.ok) return json({ html: await assetRes.text(), source: 'assets' }, 200, cors);
          return json({ error: 'Stranica nije pronadjena' }, 404, cors);
        }

        if (req.method === 'PUT') {
          const body = await req.json();
          if (!body.path || !body.html) return json({ error: 'Fali path ili html' }, 400, cors);
          await env.CONTENT.put('page:' + norm(body.path), body.html);
          return json({ success: true }, 200, cors);
        }

        if (req.method === 'DELETE') {
          const p = url.searchParams.get('path');
          if (!p) return json({ error: 'No path' }, 400, cors);
          await env.CONTENT.delete('page:' + norm(p));
          return json({ success: true }, 200, cors);
        }
      }

      if (path === '/api/upload' && req.method === 'POST') {
        if (!await auth(req, env)) return json({ error: 'Unauthorized' }, 401, cors);
        const form = await req.formData();
        const file = form.get('file');
        if (!file) return json({ error: 'Nema fajla' }, 400, cors);
        const key = 'images/' + Date.now() + '-' + file.name.replace(/[^a-zA-Z0-9._-]/g, '-');
        await env.MEDIA.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
        return json({ url: '/' + key, key }, 200, cors);
      }

      if (path === '/api/images' && req.method === 'GET') {
        if (!await auth(req, env)) return json({ error: 'Unauthorized' }, 401, cors);
        const listed = await env.MEDIA.list({ prefix: 'images/' });
        const images = listed.objects.map(o => ({ key: o.key, url: '/' + o.key, size: o.size, uploaded: o.uploaded ? o.uploaded.toISOString() : null }));
        return json({ images }, 200, cors);
      }

      if (path === '/api/delete-image' && req.method === 'POST') {
        if (!await auth(req, env)) return json({ error: 'Unauthorized' }, 401, cors);
        const body = await req.json();
        if (!body.key) return json({ error: 'No key' }, 400, cors);
        await env.MEDIA.delete(body.key);
        return json({ success: true }, 200, cors);
      }

      if (path.startsWith('/images/')) {
        const obj = await env.MEDIA.get(path.replace(/^\\//, ''));
        if (!obj) return new Response('Not found', { status: 404 });
        const h = new Headers();
        obj.writeHttpMetadata(h);
        h.set('Cache-Control', 'public, max-age=31536000');
        return new Response(obj.body, { headers: h });
      }

      if (path === '/admin' || path === '/admin/') {
        const html = await env.ASSETS.fetch(new Request(new URL('/admin/index.html', url.origin).toString()));
        return new Response(await html.text(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      if (path.includes('.')) return env.ASSETS.fetch(req);

      const n = norm(path);
      const kv = await env.CONTENT.get('page:' + n);
      if (kv) return new Response(kv, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      return env.ASSETS.fetch(new Request(new URL(toAssetPath(n), url.origin).toString()));

    } catch (err) {
      return json({ error: err.message, stack: err.stack }, 500, cors);
    }
  }
};
