/**
 * PW API proxy — Cloudflare Worker (single file)
 * Crafted by Shivam Singh
 *
 * Every request is forwarded to api.penpencil.co with the caller's bearer token,
 * so PW itself decides what that account may see.
 *
 * CATALOG routes  (shared PW_TOKEN + ACCESS_KEY may be used):
 *   /batch/:batchId/details
 *   /batch/:batchId/schedule
 *   /batch/:batchId/announcements?page=1
 *   /batch/:batchId/subject/:subjectId/topics?page=1&limit=20&type=UNITS
 *
 * CONTENT routes  (the visitor's OWN token is required: ?token= or Authorization header.
 *                  The shared key is refused here on purpose):
 *   /batch/:batchId/subject/:subjectSlug/lectures?tag=<topic-slug>&page=1
 *   /batch/:batchId/subject/:subjectSlug/notes?tag=<topic-slug>&page=1
 *   /batch/:batchId/subject/:subjectSlug/dpp?tag=<topic-slug>&page=1
 *   /batch/:batchId/subject/:subjectId/files?type=NOTES&tagId=<topic-id>&skip=0&limit=20   (PW v3: returns file keys)
 *   /batch/:batchId/subject/:subjectId/schedule/:scheduleId/slides
 *   /p/<upstream path>?<query>                       (generic pass-through, own token only)
 *
 * For notes / dpp / slides the worker adds "fileUrl" (baseUrl + key) to every file object
 * PW returns. If PW returns an empty key for that account, fileUrl is null: the worker
 * never invents or looks up links from anywhere else.
 */

const UPSTREAM  = 'https://api.penpencil.co';     // the ONLY host this worker will ever call
const CLIENT_ID = '5eb393ee95fab7468a79d189';

/**
 * path     : URL on this worker (":name" = variable part)
 * upstream : URL on the upstream API (same ":name" variables)
 * query    : fixed/default query parameters sent upstream
 * allow    : query parameters the caller may set -> { callerName: upstreamName }
 * userOnly : true = needs the visitor's own token (shared key refused)
 * addUrls  : true = add fileUrl to file objects in the JSON response
 */
const ROUTES = [
  { path: '/batch/:batchId/details',
    upstream: '/v3/batches/:batchId/details' },

  { path: '/batch/:batchId/schedule',
    upstream: '/v1/batches/:batchId/todays-schedule',
    query: { isNewStudyMaterialFlow: 'true' } },

  { path: '/batch/:batchId/announcements',
    upstream: '/v1/batches/:batchId/announcement',
    query: { page: '1' }, allow: { page: 'page' } },

  { path: '/batch/:batchId/subject/:subjectId/topics',
    upstream: '/batch-service/v1/batch-tags/:batchId/subject/:subjectId/topics',
    query: { page: '1', batchTagType: 'UNITS', limit: '20' },
    allow: { page: 'page', limit: 'limit', type: 'batchTagType' } },

  { path: '/batch/:batchId/subject/:subjectSlug/lectures',
    upstream: '/v2/batches/:batchId/subject/:subjectSlug/contents',
    query: { contentType: 'videos', page: '1' },
    allow: { tag: 'tag', page: 'page' }, userOnly: true },

  { path: '/batch/:batchId/subject/:subjectSlug/notes',
    upstream: '/v2/batches/:batchId/subject/:subjectSlug/contents',
    query: { contentType: 'notes', page: '1' },
    allow: { tag: 'tag', page: 'page' }, userOnly: true, addUrls: true },

  { path: '/batch/:batchId/subject/:subjectSlug/dpp',
    upstream: '/v2/batches/:batchId/subject/:subjectSlug/contents',
    query: { contentType: 'DppNotes', page: '1' },
    allow: { tag: 'tag', page: 'page' }, userOnly: true, addUrls: true },

  { path: '/batch/:batchId/subject/:subjectId/files',
    upstream: '/batch-service/v3/batch-subject-schedules/:batchId/subject/:subjectId/contents',
    query: { skip: '0', limit: '20', contentType: 'NOTES', contentFilter: 'ALL' },
    allow: { skip: 'skip', limit: 'limit', type: 'contentType', filter: 'contentFilter', tagId: 'tagId' },
    userOnly: true, addUrls: true },

  { path: '/batch/:batchId/subject/:subjectId/schedule/:scheduleId/slides',
    upstream: '/v1/batches/:batchId/subject/:subjectId/schedule/:scheduleId/slides',
    userOnly: true, addUrls: true },
];

const ID = /^[A-Za-z0-9_-]{1,100}$/;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Max-Age': '86400',
};

/* ------------------------------------------------------------------ main */

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (request.method !== 'GET') return json({ success: false, message: 'Only GET is supported' }, 405);

    const url  = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (path === '/') return json(docs(url.origin));

    const auth = getToken(request, url, env);
    if (!auth.ok) return json({ success: false, message: auth.message }, auth.status);

    const match = path.startsWith('/p/') ? passthrough(path, url) : matchRoute(path, url);
    if (!match) {
      return json({ success: false, message: 'Unknown route', hint: 'Open / for the list of routes' }, 404);
    }

    if (match.route.userOnly && auth.shared) {
      return json({
        success: false,
        message: 'This route needs the visitor\'s own PW token (?token=... or an Authorization header). The shared access key is not accepted here.',
      }, 403);
    }
    return forward(match.url, auth.token, match.route);
  },
};

/* ------------------------------------------------------------------ auth */

function getToken(request, url, env) {
  let t = url.searchParams.get('token') || request.headers.get('Authorization') || '';
  t = t.replace(/^Bearer\s+/i, '').trim();
  if (t) return { ok: true, token: t, shared: false };

  // Optional: a shared token stored as a Worker secret, protected by an access key.
  if (env && env.PW_TOKEN && env.ACCESS_KEY) {
    if (url.searchParams.get('key') === env.ACCESS_KEY) return { ok: true, token: env.PW_TOKEN, shared: true };
    return { ok: false, status: 401, message: 'Missing or wrong ?key=' };
  }
  return { ok: false, status: 401, message: 'Missing token. Add ?token=YOUR_BEARER_TOKEN to the URL.' };
}

/* --------------------------------------------------------------- routing */

function matchRoute(path, url) {
  const seg = path.split('/').filter(Boolean);

  for (const r of ROUTES) {
    const pat = r.path.split('/').filter(Boolean);
    if (pat.length !== seg.length) continue;

    const params = {};
    let ok = true;
    for (let i = 0; i < pat.length; i++) {
      if (pat[i][0] === ':') {
        if (!ID.test(seg[i])) { ok = false; break; }
        params[pat[i].slice(1)] = seg[i];
      } else if (pat[i] !== seg[i]) { ok = false; break; }
    }
    if (!ok) continue;

    const up = new URL(UPSTREAM + r.upstream.replace(/:(\w+)/g, (_, k) => params[k]));
    const q = { ...(r.query || {}) };
    for (const [from, to] of Object.entries(r.allow || {})) {
      if (url.searchParams.has(from)) q[to] = url.searchParams.get(from);
    }
    for (const [k, v] of Object.entries(q)) up.searchParams.set(k, v);
    return { url: up, route: r };
  }
  return null;
}

/** /p/v1/batches/... -> https://api.penpencil.co/v1/batches/... (own token only) */
function passthrough(path, url) {
  const p = path.slice(2);                          // remove "/p"
  if (!/^\/[A-Za-z0-9_\-./]+$/.test(p) || p.includes('..')) return null;
  const up = new URL(UPSTREAM + p);
  for (const [k, v] of url.searchParams) {
    if (k !== 'token' && k !== 'key') up.searchParams.append(k, v);
  }
  return { url: up, route: { userOnly: true } };
}

/* --------------------------------------------------------------- upstream */

async function forward(target, token, route) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 25000);
  try {
    const res = await fetch(target.toString(), {
      method: 'GET',
      signal: ctrl.signal,
      headers: {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token,
        'client-type': 'WEB',
        'client-id': CLIENT_ID,
        'client-version': '5.2.18',
        'client-platform': 'MOBILE',
        'X-SDK-Version': '0.0.28',
        'randomId': crypto.randomUUID(),
        'Referer': 'https://www.pw.live/',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
      },
    });

    let body = await res.text();
    const type = res.headers.get('content-type') || 'application/json; charset=utf-8';

    if (route && route.addUrls && res.ok && type.includes('json')) {
      try {
        const data = JSON.parse(body);
        addFileUrls(data);
        body = JSON.stringify(data);
      } catch (_) { /* leave body untouched if it is not valid JSON */ }
    }

    return new Response(body, {
      status: res.status,
      headers: { ...CORS, 'Content-Type': type, 'Cache-Control': 'no-store' },
    });
  } catch (e) {
    const msg = e && e.name === 'AbortError' ? 'Upstream timed out' : 'Upstream request failed: ' + (e && e.message);
    return json({ success: false, message: msg }, 502);
  } finally {
    clearTimeout(timer);
  }
}

/** Adds fileUrl = baseUrl + key to every file object; null when PW gave no key. */
function addFileUrls(node) {
  if (Array.isArray(node)) { node.forEach(addFileUrls); return; }
  if (node && typeof node === 'object') {
    if (typeof node.baseUrl === 'string' && 'key' in node) {
      node.fileUrl = node.key
        ? node.baseUrl.replace(/\/+$/, '') + '/' + String(node.key).replace(/^\/+/, '')
        : null;
    }
    for (const v of Object.values(node)) addFileUrls(v);
  }
}

/* ---------------------------------------------------------------- helpers */

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function docs(origin) {
  return {
    name: 'PW API proxy',
    craftedBy: 'Shivam Singh',
    usage: 'Add ?token=YOUR_OWN_PW_TOKEN (or an Authorization: Bearer header). PW decides what that account can see.',
    routes: ROUTES.map((r) => ({
      url: origin + r.path,
      upstream: r.upstream,
      defaults: r.query || {},
      optionalQuery: Object.keys(r.allow || {}),
      needsOwnToken: !!r.userOnly,
      addsFileUrl: !!r.addUrls,
    })),
    passthrough: origin + '/p/<upstream path>?<query>&token=...   (own token only)',
    examples: [
      origin + '/batch/6774ebb37aa1a60276d43e7c/subject/chemistry-786226/lectures?tag=atoms-and-molecules-and-structure-of-atom-451322&page=1&token=XXXX',
      origin + '/batch/6774ebb37aa1a60276d43e7c/subject/chemistry-786226/notes?tag=atoms-and-molecules-and-structure-of-atom-451322&page=1&token=XXXX',
      origin + '/batch/6774ebb37aa1a60276d43e7c/subject/chemistry-786226/dpp?tag=atoms-and-molecules-and-structure-of-atom-451322&page=1&token=XXXX',
      origin + '/batch/6774ebb37aa1a60276d43e7c/subject/67790d75246e77380dadc7cb/files?type=NOTES&tagId=67fb56e01684fd977be815b6&skip=0&limit=20&token=XXXX',
      origin + '/batch/6774ebb37aa1a60276d43e7c/subject/67790d75246e77380dadc7cb/schedule/690b593704f454580b810044/slides?token=XXXX',
    ],
  };
}
