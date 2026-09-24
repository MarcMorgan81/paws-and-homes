export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const key = url.pathname.replace(/^\/uploads\//, '');
  const obj = await env.UPLOADS.get(key);
  if (!obj) return new Response('Not found', { status: 404 });
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set('etag', obj.httpEtag);
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  return new Response(obj.body, { headers });
}

