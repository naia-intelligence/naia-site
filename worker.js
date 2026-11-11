const PAGES = [
  { path: '/', name: 'Početna' },
  { path: '/o-nama/', name: 'O nama' },
  { path: '/program/', name: 'Program' },
  { path: '/contact/', name: 'Kontakt' },
  { path: '/ritualni-vodic-28-dana-povratka-sebi/', name: 'Ritualni vodič' },
];

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

function normalizePath(path) {
  if (!path || path === '/') return '/';
  let p = path.startsWith('/') ? path : '/' + path;
  if (!p.endsWith('/') && !p.includes('.')) p += '/';
  return p;
}

async function hmacSign(data, key) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw', enc.encode(key),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function createToken(password) {
  const payload = btoa(JSON.stringify({ exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const sig = await hmacSign(payload, password);
  return `${payload}.${sig}`;
}

async function verifyToken(token, password) {
  if (!token || !password) return false;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;
  const expected = await hmacSign(payload, password);
  if (sig !== expected) return false;
  try {
    const data = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    return data.exp > Date.now();
  } catch {
    return false;
  }
}

function getToken(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/naia_auth=([^;]+)/);
  return match ? match[1] : null;
}

async function isAuthed(request, env) {
  return verifyToken(getToken(request), env.ADMIN_PASSWORD);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': url.origin,
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Credentials': 'true',
        },
      });
    }

    const cors = {
      'Access-Control-Allow-Origin': url.origin,
      'Access-Control-Allow-Credentials': 'true',
    };

    if (path === '/api/login' && request.method === 'POST')
      return handleLogin(request, env, cors);

    if (path === '/api/verify' && request.method === 'GET')
      return handleVerify(request, env, cors);

    if (path === '/api/pages' && request.method === 'GET')
      return handleListPages(request, env, cors);

    if (path === '/api/page')
      return handlePage(request, env, cors, url);

    if (path === '/api/upload' && request.method === 'POST')
      return handleUpload(request, env, cors);

    if (path === '/api/images' && request.method === 'GET')
      return handleListImages(request, env, cors);

    if (path === '/api/delete-image' && request.method === 'POST')
      return handleDeleteImage(request, env, cors);

    if (path.startsWith('/images/'))
      return serveR2Image(path, env);

    if (path.startsWith('/admin') || path.includes('.'))
      return env.ASSETS.fetch(request);

    const normalized = normalizePath(path);
    const kvContent = await env.CONTENT.get(`page:${normalized}`);
    if (kvContent) {
      return new Response(kvContent, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    return env.ASSETS.fetch(request);
  },
};

async function handleLogin(request, env, cors) {
  if (!env.ADMIN_PASSWORD) {
    return jsonResponse({
      error: 'ADMIN_PASSWORD nije postavljen.'
    }, 500, cors);
  }
  const body = await request.json();
  if (body.password !== env.ADMIN_PASSWORD) {
    return jsonResponse({ error: 'Pogrešna lozinka' }, 401, cors);
  }
  const token = await createToken(env.ADMIN_PASSWORD);
  return jsonResponse({ success: true }, 200, {
    ...cors,
    'Set-Cookie': `naia_auth=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`,
  });
}

async function handleVerify(request, env, cors) {
  const authed = await isAuthed(request, env);
  return jsonResponse({ authed }, 200, cors);
}

async function handleListPages(request, env, cors) {
  if (!await isAuthed(request, env))
    return jsonResponse({ error: 'Unauthorized' }, 401, cors);

  const pages = [];
  for (const page of PAGES) {
    const kv = await env.CONTENT.get(`page:${page.path}`);
    pages.push({ ...page, edited: !!kv });
  }
  return jsonResponse({ pages }, 200, cors);
}

async function handlePage(request, env, cors, url) {
  if (!await isAuthed(request, env))
    return jsonResponse({ error: 'Unauthorized' }, 401, cors);

  if (request.method === 'GET') {
    const path = url.searchParams.get('path');
    const original = url.searchParams.get('original') === 'true';
    if (!path) return jsonResponse({ error: 'No path' }, 400, cors);

    const normalized = normalizePath(path);

    if (!original) {
      const kv = await env.CONTENT.get(`page:${normalized}`);
      if (kv) return jsonResponse({ html: kv, source: 'kv' }, 200, cors);
    }

    const assetUrl = new URL(normalized, url.origin);
    const assetRes = await env.ASSETS.fetch(new Request(assetUrl.toString()));
    if (assetRes.ok) {
      const html = await assetRes.text();
      return jsonResponse({ html, source: 'assets' }, 200, cors);
    }
    return jsonResponse({ error: 'Stranica nije pronađena' }, 404, cors);
  }

  if (request.method === 'PUT') {
    const body = await request.json();
    if (!body.path || !body.html)
      return jsonResponse({ error: 'Fali path ili html' }, 400, cors);

    const normalized = normalizePath(body.path);
    await env.CONTENT.put(`page:${normalized}`, body.html);
    return jsonResponse({ success: true }, 200, cors);
  }

  if (request.method === 'DELETE') {
    const path = url.searchParams.get('path');
    if (!path) return jsonResponse({ error: 'No path' }, 400, cors);

    const normalized = normalizePath(path);
    await env.CONTENT.delete(`page:${normalized}`);
    return jsonResponse({ success: true }, 200, cors);
  }

  return jsonResponse({ error: 'Method not allowed' }, 405, cors);
}

async function handleUpload(request, env, cors) {
  if (!await isAuthed(request, env))
    return jsonResponse({ error: 'Unauthorized' }, 401, cors);

  const formData = await request.formData();
  const file = formData.get('file');
  if (!file) return jsonResponse({ error: 'Nema fajla' }, 400, cors);

  const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '-');
  const key = `images/${Date.now()}-${safeName}`;

  await env.MEDIA.put(key, file.stream(), {
    httpMetadata: { contentType: file.type },
  });

  return jsonResponse({ url: `/${key}`, key }, 200, cors);
}

async function handleListImages(request, env, cors) {
  if (!await isAuthed(request, env))
    return jsonResponse({ error: 'Unauthorized' }, 401, cors);

  const listed = await env.MEDIA.list({ prefix: 'images/' });
  const images = listed.objects.map(obj => ({
    key: obj.key,
    url: `/${obj.key}`,
    size: obj.size,
    uploaded: obj.uploaded ? obj.uploaded.toISOString() : null,
  }));
  return jsonResponse({ images }, 200, cors);
}

async function handleDeleteImage(request, env, cors) {
  if (!await isAuthed(request, env))
    return jsonResponse({ error: 'Unauthorized' }, 401, cors);

  const body = await request.json();
  if (!body.key) return jsonResponse({ error: 'No key' }, 400, cors);

  await env.MEDIA.delete(body.key);
  return jsonResponse({ success: true }, 200, cors);
}

async function serveR2Image(path, env) {
  const key = path.replace(/^\//, '');
  const object = await env.MEDIA.get(key);
  if (!object) return new Response('Not found', { status: 404 });

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('Cache-Control', 'public, max-age=31536000');
  return new Response(object.body, { headers });
}
