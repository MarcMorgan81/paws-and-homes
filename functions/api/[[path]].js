// Paws and Homes API — runs as a Cloudflare Pages Function.
// Every request to /api/* is routed through here. D1 is bound as env.DB
// (set this up in the Pages project settings — see README).

const DAY = 24 * 60 * 60 * 1000;
const LISTING_LENGTH_DAYS = 30;
const FEE = 5;
const LOCKED_FIELDS = ['type', 'breed', 'title', 'emoji'];
const MAX_IMAGE_BYTES = 5 * 1024 * 1024; // 5MB per photo
const MAX_IMAGES_PER_LISTING = 6;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function err(message, status = 400) {
  return json({ error: message }, status);
}
// --- password hashing (PBKDF2 via Web Crypto — no external deps needed) ---
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex
    ? new Uint8Array(saltHex.match(/.{2}/g).map((b) => parseInt(b, 16)))
    : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const hashHex = [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const saltHexOut = [...salt].map((b) => b.toString(16).padStart(2, '0')).join('');
  return { hash: hashHex, salt: saltHexOut };
}
async function verifyPassword(password, hash, salt) {
  const { hash: check } = await hashPassword(password, salt);
  return check === hash;
}
