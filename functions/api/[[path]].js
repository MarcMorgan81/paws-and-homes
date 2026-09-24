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

async function stripeCall(env, method, path, bodyParams) {
  const body = bodyParams ? new URLSearchParams(flattenStripeParams(bodyParams)) : undefined;
  const res = await fetch(`https://api.stripe.com/v1/${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || 'Stripe request failed');
  return data;
}
function flattenStripeParams(obj, prefix = '') {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}[${k}]` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) Object.assign(out, flattenStripeParams(v, key));
    else if (Array.isArray(v)) v.forEach((item, i) => Object.assign(out, typeof item === 'object' ? flattenStripeParams(item, `${key}[${i}]`) : { [`${key}[${i}]`]: item }));
    else out[key] = v;
  }
  return out;
}

// Verifies Stripe's webhook signature per https://docs.stripe.com/webhooks#verify-manually
async function verifyStripeSignature(payload, sigHeader, secret) {
  const parts = Object.fromEntries(sigHeader.split(',').map(p => p.split('=')));
  const signedPayload = `${parts.t}.${payload}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
  const expected = [...new Uint8Array(sigBytes)].map(b => b.toString(16).padStart(2, '0')).join('');
  return expected === parts.v1;
}

async function createCheckout(env, { priceId, metadata, successPath, customerEmail }) {
  return stripeCall(env, 'POST', 'checkout/sessions', {
    mode: 'payment',
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `https://pawsandhomes.co.uk/${successPath}`,
    cancel_url: `https://pawsandhomes.co.uk/#myads`,
    customer_email: customerEmail,
    metadata,
  });
}
const PRICES = {
  listing_fee: 'price_1UJ6tCH95otPhP9KN9Eo1meb',
  boost_3: 'price_1UJ6tGH95otPhP9K4tgv6Ptg',
  boost_7: 'price_1UJAr0H95otPhP9KqqDLuLtF',
  boost_14: 'price_1UJAr3H95otPhP9KJvI4lmFP',
};

function newId(prefix) {
  return prefix + '_' + crypto.randomUUID().replace(/-/g, '').slice(0, 20);
}

// Sends via Resend if RESEND_API_KEY is set (Pages env var); otherwise logs only,
// so the reset flow still works end-to-end for testing before an email provider is wired up.
async function sendEmail(env, to, subject, html) {
  if (!env.RESEND_API_KEY) { console.log('[email not sent — no RESEND_API_KEY]', to, subject); return; }
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: 'Paws and Homes <enquiries@pawsandhomes.co.uk>', to, subject, html }),
  });
}

async function getSessionUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT users.id, users.name, users.email FROM sessions
     JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?`
  ).bind(token).first();
  return row || null;
}

async function requireAdmin(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return null;
  const row = await env.DB.prepare('SELECT is_admin FROM users WHERE id = ?').bind(user.id).first();
  return row && row.is_admin ? user : null;
}

async function logHistory(env, listingId, note) {
  await env.DB.prepare('INSERT INTO listing_history (listing_id, ts, note) VALUES (?, ?, ?)')
    .bind(listingId, Date.now(), note).run();
}

function listingOut(row, history, images) {
  return {
    id: row.id, sellerId: row.seller_id, category: row.category, type: row.type, breed: row.breed, title: row.title,
    price: row.price, location: row.location, age: row.age, desc: row.description, emoji: row.emoji,
    postedAt: row.posted_at, expiresAt: row.expires_at, active: Date.now() < row.expires_at,
    boosted: row.boosted_until > Date.now(), boostedUntil: row.boosted_until,
    history: history || [], images: images || [],
  };
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, '');
  const method = request.method;

  try {
    // POST /api/signup
    if (path === 'signup' && method === 'POST') {
      const { name, email, password } = await request.json();
      if (!name || !email || !password || password.length < 6) return err('Fill in every field; password needs 6+ characters.');
      const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
      if (existing) return err('An account with that email already exists.', 409);
      const { hash, salt } = await hashPassword(password);
      const id = newId('u');
      await env.DB.prepare('INSERT INTO users (id, name, email, password_hash, password_salt, created_at) VALUES (?,?,?,?,?,?)')
        .bind(id, name, email.toLowerCase(), hash, salt, Date.now()).run();
      const token = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)').bind(token, id, Date.now()).run();
      return json({ token, user: { id, name, email: email.toLowerCase() } });
    }

    // POST /api/login
    if (path === 'login' && method === 'POST') {
      const { email, password } = await request.json();
      const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind((email || '').toLowerCase()).first();
      if (!user || !(await verifyPassword(password, user.password_hash, user.password_salt))) return err('Invalid email or password.', 401);
      if (user.is_blocked) return err('This account has been suspended. Contact enquiries@pawsandhomes.co.uk if you believe this is a mistake.', 403);
      const token = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)').bind(token, user.id, Date.now()).run();
      return json({ token, user: { id: user.id, name: user.name, email: user.email } });
    }

    // POST /api/logout
    if (path === 'logout' && method === 'POST') {
      const auth = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
      if (auth) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(auth).run();
      return json({ ok: true });
    }

    // POST /api/forgot-password — always returns ok, whether or not the email exists,
    // so this can't be used to check which emails are registered.
    if (path === 'forgot-password' && method === 'POST') {
      const { email } = await request.json();
      const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind((email || '').toLowerCase()).first();
      if (user) {
        const token = crypto.randomUUID();
        await env.DB.prepare('INSERT INTO password_resets (token, user_id, expires_at, used, created_at) VALUES (?,?,?,0,?)')
          .bind(token, user.id, Date.now() + 60 * 60 * 1000, Date.now()).run(); // 1 hour expiry
        const link = `https://pawsandhomes.co.uk/#reset:${token}`;
        await sendEmail(env, user.email, 'Reset your Paws and Homes password',
          `<p>Click below to reset your password. This link expires in 1 hour.</p><p><a href="${link}">${link}</a></p>`);
      }
      return json({ ok: true });
    }

    // POST /api/reset-password
    if (path === 'reset-password' && method === 'POST') {
      const { token, password } = await request.json();
      if (!password || password.length < 6) return err('Password needs to be at least 6 characters.');
      const reset = await env.DB.prepare('SELECT * FROM password_resets WHERE token = ?').bind(token).first();
      if (!reset || reset.used || reset.expires_at < Date.now()) return err('This reset link is invalid or has expired.', 400);
      const { hash, salt } = await hashPassword(password);
      await env.DB.prepare('UPDATE users SET password_hash=?, password_salt=? WHERE id=?').bind(hash, salt, reset.user_id).run();
      await env.DB.prepare('UPDATE password_resets SET used=1 WHERE token=?').bind(token).run();
      await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(reset.user_id).run(); // log out everywhere on reset
      return json({ ok: true });
    }

    // GET /api/breeds?type=Dogs
    if (path === 'breeds' && method === 'GET') {
      const type = url.searchParams.get('type');
      const rows = type
        ? (await env.DB.prepare('SELECT name FROM breeds WHERE type = ? ORDER BY name').bind(type).all()).results
        : (await env.DB.prepare('SELECT type, name FROM breeds ORDER BY type, name').all()).results;
      return json(rows.map(r => r.name || r));
    }
    if (path === 'listings' && method === 'GET') {
      const type = url.searchParams.get('type');
      const q = (url.searchParams.get('q') || '').toLowerCase();
      let sql = 'SELECT * FROM listings WHERE expires_at > ?';
      const binds = [Date.now()];
      if (type && type !== 'All') { sql += ' AND type = ?'; binds.push(type); }
      sql += ' ORDER BY (boosted_until > ?) DESC, posted_at DESC';
      binds.push(Date.now());
      const { results } = await env.DB.prepare(sql).bind(...binds).all();
      let rows = results;
      if (q) rows = rows.filter(r => (r.breed + r.title + r.location).toLowerCase().includes(q));
      return json(rows.map(r => listingOut(r)));
    }

    // GET /api/my-listings (auth)
    if (path === 'my-listings' && method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return err('Not logged in.', 401);
      const { results } = await env.DB.prepare('SELECT * FROM listings WHERE seller_id = ? ORDER BY posted_at DESC').bind(user.id).all();
      return json(results.map(r => listingOut(r)));
    }

    // POST /api/listings (auth) — create. Free accounts go live immediately;
    // paid accounts are created as "pending" (expires_at=0, hidden from browse)
    // and only activated when the webhook confirms payment.
    if (path === 'listings' && method === 'POST') {
      const user = await getSessionUser(request, env);
      if (!user) return err('Not logged in.', 401);
      const b = await request.json();
      if (!b.title || !b.breed || !b.type || !b.price || !b.location || !b.desc) return err('Please fill in every field.');
      const now = Date.now();
      const id = newId('l');
      const category = b.category === 'Stud Service' ? 'Stud Service' : 'For Sale';
      const isFree = (await env.DB.prepare('SELECT is_free_account FROM users WHERE id = ?').bind(user.id).first()).is_free_account;
      const expiresAt = isFree ? now + LISTING_LENGTH_DAYS * DAY : 0; // 0 = pending payment
      await env.DB.prepare(
        `INSERT INTO listings (id, seller_id, category, type, breed, title, price, location, age, description, emoji, posted_at, expires_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(id, user.id, category, b.type, b.breed, b.title, b.price, b.location, b.age || 'Not specified', b.desc, b.emoji || '🐾', now, expiresAt).run();

      if (isFree) {
        await logHistory(env, id, 'Ad published (free account, no fee)');
        return json({ id });
      }
      await logHistory(env, id, 'Ad created — awaiting payment');
      const session = await createCheckout(env, {
        priceId: PRICES.listing_fee,
        metadata: { action: 'create_listing', listingId: id, userId: user.id },
        successPath: `#listing:${id}`,
        customerEmail: user.email,
      });
      return json({ id, checkoutUrl: session.url });
    }

    // POST /api/listings/:id/images — multipart form upload, one file per call
    const imageMatch = path.match(/^listings\/([^/]+)\/images$/);
    if (imageMatch && method === 'POST') {
      const id = imageMatch[1];
      const user = await getSessionUser(request, env);
      if (!user) return err('Not logged in.', 401);
      const row = await env.DB.prepare('SELECT * FROM listings WHERE id = ?').bind(id).first();
      if (!row) return err('Listing not found.', 404);
      if (row.seller_id !== user.id) return err('Not your listing.', 403);
      const count = (await env.DB.prepare('SELECT COUNT(*) as c FROM listing_images WHERE listing_id = ?').bind(id).first()).c;
      if (count >= MAX_IMAGES_PER_LISTING) return err(`Max ${MAX_IMAGES_PER_LISTING} photos per listing.`, 400);

      const form = await request.formData();
      const file = form.get('file');
      if (!file || typeof file === 'string') return err('No file provided.', 400);
      if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) return err('Only JPEG, PNG or WEBP images are allowed.', 400);
      if (file.size > MAX_IMAGE_BYTES) return err(`Image too large — max ${MAX_IMAGE_BYTES / 1024 / 1024}MB.`, 400);

      const key = `${id}/${crypto.randomUUID()}.${file.type.split('/')[1]}`;
      await env.UPLOADS.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } });
      const publicUrl = `/uploads/${key}`;
      await env.DB.prepare('INSERT INTO listing_images (listing_id, url, size_bytes, uploaded_at) VALUES (?,?,?,?)')
        .bind(id, publicUrl, file.size, Date.now()).run();
      return json({ url: publicUrl });
    }

    // Match /api/listings/:id  and  /api/listings/:id/renew
    const listingMatch = path.match(/^listings\/([^/]+)(?:\/(renew))?$/);
    if (listingMatch) {
      const id = listingMatch[1];
      const isRenew = listingMatch[2] === 'renew';

      if (!isRenew && method === 'GET') {
        const row = await env.DB.prepare('SELECT * FROM listings WHERE id = ?').bind(id).first();
        if (!row) return err('Not found.', 404);
        const { results: hist } = await env.DB.prepare('SELECT ts, note FROM listing_history WHERE listing_id = ? ORDER BY ts DESC').bind(id).all();
        const { results: imgs } = await env.DB.prepare('SELECT url FROM listing_images WHERE listing_id = ? ORDER BY uploaded_at').bind(id).all();
        return json(listingOut(row, hist, imgs.map(i => i.url)));
      }

      if (isRenew && method === 'POST') {
        const user = await getSessionUser(request, env);
        if (!user) return err('Not logged in.', 401);
        const row = await env.DB.prepare('SELECT * FROM listings WHERE id = ?').bind(id).first();
        if (!row) return err('Not found.', 404);
        if (row.seller_id !== user.id) return err('Not your listing.', 403);
        const isFree = (await env.DB.prepare('SELECT is_free_account FROM users WHERE id = ?').bind(user.id).first()).is_free_account;
        if (isFree) {
          await env.DB.prepare('UPDATE listings SET expires_at = ? WHERE id = ?').bind(Date.now() + LISTING_LENGTH_DAYS * DAY, id).run();
          await logHistory(env, id, 'Renewed (free account, no fee)');
          return json({ ok: true });
        }
        const session = await createCheckout(env, {
          priceId: PRICES.listing_fee,
          metadata: { action: 'renew', listingId: id, userId: user.id },
          successPath: `#listing:${id}`,
          customerEmail: user.email,
        });
        return json({ checkoutUrl: session.url });
      }

      if (!isRenew && method === 'PATCH') {
        const user = await getSessionUser(request, env);
        if (!user) return err('Not logged in.', 401);
        const row = await env.DB.prepare('SELECT * FROM listings WHERE id = ?').bind(id).first();
        if (!row) return err('Not found.', 404);
        if (row.seller_id !== user.id) return err('Not your listing.', 403);
        const b = await request.json();

        // Server decides whether this is a "core" (fee-triggering) change —
        // never trust a client-sent flag for this, always diff against the stored row.
        const coreChanged = LOCKED_FIELDS.some((f) => {
          const col = f === 'desc' ? 'description' : f;
          return b[f] !== undefined && String(b[f]) !== String(row[col]);
        });
        const isFree = (await env.DB.prepare('SELECT is_free_account FROM users WHERE id = ?').bind(user.id).first()).is_free_account;

        // Free-to-edit fields always apply immediately, regardless of payment status.
        await env.DB.prepare('UPDATE listings SET price=?, age=?, location=?, description=? WHERE id=?')
          .bind(b.price ?? row.price, b.age ?? row.age, b.location ?? row.location, b.desc ?? row.description, id).run();

        if (!coreChanged) {
          await logHistory(env, id, 'Details updated (free edit)');
          return json({ ok: true, coreChanged: false });
        }
        if (isFree) {
          await env.DB.prepare('UPDATE listings SET type=?, breed=?, title=?, emoji=?, expires_at=? WHERE id=?')
            .bind(b.type ?? row.type, b.breed ?? row.breed, b.title ?? row.title, b.emoji ?? row.emoji, Date.now() + LISTING_LENGTH_DAYS * DAY, id).run();
          await logHistory(env, id, 'Animal details changed (free account, no fee), listing relisted');
          return json({ ok: true, coreChanged: true });
        }
        // Paid: don't apply the core change yet — the webhook applies it once payment is confirmed.
        const session = await createCheckout(env, {
          priceId: PRICES.listing_fee,
          metadata: {
            action: 'relist', listingId: id, userId: user.id,
            newType: b.type ?? row.type, newBreed: b.breed ?? row.breed,
            newTitle: b.title ?? row.title, newEmoji: b.emoji ?? row.emoji,
          },
          successPath: `#listing:${id}`,
          customerEmail: user.email,
        });
        return json({ ok: true, coreChanged: true, checkoutUrl: session.url });
      }
    }

    // --- Admin ---
    if (path === 'admin/stats' && method === 'GET') {
      const admin = await requireAdmin(request, env);
      if (!admin) return err('Admin access required.', 403);
      const now = Date.now();
      const weekAgo = now - 7 * DAY;
      const totalUsers = (await env.DB.prepare('SELECT COUNT(*) c FROM users').first()).c;
      const signupsThisWeek = (await env.DB.prepare('SELECT COUNT(*) c FROM users WHERE created_at > ?').bind(weekAgo).first()).c;
      const activeListings = (await env.DB.prepare('SELECT COUNT(*) c FROM listings WHERE expires_at > ?').bind(now).first()).c;
      const totalListings = (await env.DB.prepare('SELECT COUNT(*) c FROM listings').first()).c;
      const adsThisWeek = (await env.DB.prepare('SELECT COUNT(*) c FROM listings WHERE posted_at > ?').bind(weekAgo).first()).c;
      const income = (await env.DB.prepare('SELECT COALESCE(SUM(amount),0) t FROM payments').first()).t;
      const incomeThisWeek = (await env.DB.prepare('SELECT COALESCE(SUM(amount),0) t FROM payments WHERE created_at > ?').bind(weekAgo).first()).t;
      const boostsSold = (await env.DB.prepare("SELECT COUNT(*) c FROM payments WHERE type = 'boost'").first()).c;
      const openComplaints = (await env.DB.prepare("SELECT COUNT(*) c FROM complaints WHERE status = 'open'").first()).c;
      return json({ totalUsers, signupsThisWeek, activeListings, totalListings, adsThisWeek, income, incomeThisWeek, boostsSold, openComplaints });
    }

    const blockMatch = path.match(/^admin\/(block|unblock)\/([^/]+)$/);
    if (blockMatch && method === 'POST') {
      const admin = await requireAdmin(request, env);
      if (!admin) return err('Admin access required.', 403);
      await env.DB.prepare('UPDATE users SET is_blocked = ? WHERE id = ?').bind(blockMatch[1] === 'block' ? 1 : 0, blockMatch[2]).run();
      return json({ ok: true });
    }

    if (path === 'admin/complaints' && method === 'GET') {
      const admin = await requireAdmin(request, env);
      if (!admin) return err('Admin access required.', 403);
      const { results } = await env.DB.prepare('SELECT * FROM complaints ORDER BY created_at DESC').all();
      return json(results);
    }

    const complaintStatusMatch = path.match(/^admin\/complaints\/([^/]+)\/status$/);
    if (complaintStatusMatch && method === 'POST') {
      const admin = await requireAdmin(request, env);
      if (!admin) return err('Admin access required.', 403);
      const { status } = await request.json();
      if (!['open', 'reviewing', 'resolved'].includes(status)) return err('Invalid status.');
      await env.DB.prepare('UPDATE complaints SET status = ? WHERE id = ?').bind(status, complaintStatusMatch[1]).run();
      return json({ ok: true });
    }

    // --- Complaints (public — anyone can report, account or not) ---
    if (path === 'complaints' && method === 'POST') {
      const b = await request.json();
      if (!b.reporterEmail || !b.description) return err('Please provide your email and a description.');
      const id = newId('c');
      await env.DB.prepare(
        `INSERT INTO complaints (id, reporter_name, reporter_email, against_user_id, against_listing_id, description, evidence_json, status, created_at)
         VALUES (?,?,?,?,?,?,?,?,?)`
      ).bind(id, b.reporterName || null, b.reporterEmail, b.againstUserId || null, b.againstListingId || null,
             b.description, JSON.stringify(b.evidenceUrls || []), 'open', Date.now()).run();
      return json({ ok: true, id });
    }

    // POST /api/upload-evidence — for complaint screenshots, no login required
    if (path === 'upload-evidence' && method === 'POST') {
      const form = await request.formData();
      const file = form.get('file');
      if (!file || typeof file === 'string') return err('No file provided.', 400);
      if (file.size > MAX_IMAGE_BYTES) return err(`File too large — max ${MAX_IMAGE_BYTES / 1024 / 1024}MB.`, 400);
      const key = `evidence/${crypto.randomUUID()}`;
      await env.UPLOADS.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
      return json({ url: `/uploads/${key}` });
    }

    // --- Messages ---
    const sendMsgMatch = path.match(/^listings\/([^/]+)\/messages$/);
    if (sendMsgMatch && method === 'POST') {
      const user = await getSessionUser(request, env);
      if (!user) return err('Not logged in.', 401);
      const listing = await env.DB.prepare('SELECT * FROM listings WHERE id = ?').bind(sendMsgMatch[1]).first();
      if (!listing) return err('Listing not found.', 404);
      const { body } = await request.json();
      if (!body || !body.trim()) return err('Message cannot be empty.');
      const recipientId = user.id === listing.seller_id ? null : listing.seller_id; // sellers reply via thread, not implemented here yet — buyer-to-seller only for now
      if (!recipientId) return err('Use the thread reply, not this endpoint, to message your own listing.');
      await env.DB.prepare('INSERT INTO messages (listing_id, sender_id, recipient_id, body, created_at) VALUES (?,?,?,?,?)')
        .bind(listing.id, user.id, recipientId, body.trim(), Date.now()).run();
      await env.DB.prepare('INSERT INTO notifications (user_id, type, message, listing_id, created_at) VALUES (?,?,?,?,?)')
        .bind(recipientId, 'message', `New message about "${listing.title}"`, listing.id, Date.now()).run();
      return json({ ok: true });
    }

    if (path === 'conversations' && method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return err('Not logged in.', 401);
      const { results } = await env.DB.prepare(
        `SELECT m.listing_id, l.title, l.emoji,
                CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END as other_user_id,
                MAX(m.created_at) as last_at
         FROM messages m JOIN listings l ON l.id = m.listing_id
         WHERE m.sender_id = ? OR m.recipient_id = ?
         GROUP BY m.listing_id, other_user_id ORDER BY last_at DESC`
      ).bind(user.id, user.id, user.id).all();
      return json(results);
    }

    const threadMatch = path.match(/^messages\/([^/]+)\/([^/]+)$/);
    if (threadMatch && method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return err('Not logged in.', 401);
      const [listingId, otherUserId] = [threadMatch[1], threadMatch[2]];
      const { results } = await env.DB.prepare(
        `SELECT * FROM messages WHERE listing_id = ? AND
         ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))
         ORDER BY created_at ASC`
      ).bind(listingId, user.id, otherUserId, otherUserId, user.id).all();
      await env.DB.prepare('UPDATE messages SET read_at = ? WHERE listing_id = ? AND recipient_id = ? AND read_at IS NULL')
        .bind(Date.now(), listingId, user.id).run();
      return json(results);
    }

    // --- Notifications ---
    if (path === 'notifications' && method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return err('Not logged in.', 401);
      const { results } = await env.DB.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').bind(user.id).all();
      return json(results);
    }
    const notifReadMatch = path.match(/^notifications\/([^/]+)\/read$/);
    if (notifReadMatch && method === 'POST') {
      const user = await getSessionUser(request, env);
      if (!user) return err('Not logged in.', 401);
      await env.DB.prepare('UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ?').bind(Date.now(), notifReadMatch[1], user.id).run();
      return json({ ok: true });
    }

    // --- Boost ---
    const boostMatch = path.match(/^listings\/([^/]+)\/boost$/);
    if (boostMatch && method === 'POST') {
      const user = await getSessionUser(request, env);
      if (!user) return err('Not logged in.', 401);
      const row = await env.DB.prepare('SELECT * FROM listings WHERE id = ?').bind(boostMatch[1]).first();
      if (!row) return err('Not found.', 404);
      if (row.seller_id !== user.id) return err('Not your listing.', 403);
      const { days } = await request.json(); // 3, 7, or 14
      const priceKey = { 3: 'boost_3', 7: 'boost_7', 14: 'boost_14' }[days];
      if (!priceKey) return err('Invalid boost length.');
      const isFree = (await env.DB.prepare('SELECT is_free_account FROM users WHERE id = ?').bind(user.id).first()).is_free_account;
      if (isFree) {
        const boostedUntil = Math.max(row.boosted_until, Date.now()) + days * DAY;
        await env.DB.prepare('UPDATE listings SET boosted_until = ? WHERE id = ?').bind(boostedUntil, row.id).run();
        await logHistory(env, row.id, `Boosted for ${days} days (free account)`);
        return json({ ok: true, boostedUntil });
      }
      const session = await createCheckout(env, {
        priceId: PRICES[priceKey],
        metadata: { action: 'boost', listingId: row.id, userId: user.id, boostDays: String(days) },
        successPath: `#listing:${row.id}`,
        customerEmail: user.email,
      });
      return json({ checkoutUrl: session.url });
    }

    // --- Stripe webhook — confirms payment server-to-server, never trust the client redirect ---
    if (path === 'stripe-webhook' && method === 'POST') {
      const payload = await request.text();
      const sig = request.headers.get('Stripe-Signature') || '';
      const valid = await verifyStripeSignature(payload, sig, env.STRIPE_WEBHOOK_SECRET);
      if (!valid) return err('Invalid signature.', 400);
      const event = JSON.parse(payload);

      if (event.type === 'checkout.session.completed') {
        const s = event.data.object;
        const m = s.metadata || {};
        const amountPaid = (s.amount_total || 0) / 100;
        const payId = newId('pay');

        if (m.action === 'create_listing') {
          await env.DB.prepare('UPDATE listings SET expires_at = ? WHERE id = ?')
            .bind(Date.now() + LISTING_LENGTH_DAYS * DAY, m.listingId).run();
          await logHistory(env, m.listingId, `Ad published — £${amountPaid} charged (Stripe)`);
        } else if (m.action === 'renew') {
          await env.DB.prepare('UPDATE listings SET expires_at = ? WHERE id = ?')
            .bind(Date.now() + LISTING_LENGTH_DAYS * DAY, m.listingId).run();
          await logHistory(env, m.listingId, `Renewed — £${amountPaid} charged (Stripe)`);
        } else if (m.action === 'relist') {
          await env.DB.prepare('UPDATE listings SET type=?, breed=?, title=?, emoji=?, expires_at=? WHERE id=?')
            .bind(m.newType, m.newBreed, m.newTitle, m.newEmoji, Date.now() + LISTING_LENGTH_DAYS * DAY, m.listingId).run();
          await logHistory(env, m.listingId, `Animal details changed — £${amountPaid} charged (Stripe), listing relisted`);
        } else if (m.action === 'boost') {
          const row = await env.DB.prepare('SELECT boosted_until FROM listings WHERE id = ?').bind(m.listingId).first();
          const days = parseInt(m.boostDays, 10);
          const boostedUntil = Math.max(row?.boosted_until || 0, Date.now()) + days * DAY;
          await env.DB.prepare('UPDATE listings SET boosted_until = ? WHERE id = ?').bind(boostedUntil, m.listingId).run();
          await logHistory(env, m.listingId, `Boosted for ${days} days — £${amountPaid} charged (Stripe)`);
        }

        if (m.action) {
          await env.DB.prepare('INSERT INTO payments (id, user_id, listing_id, type, amount, stripe_payment_intent_id, created_at) VALUES (?,?,?,?,?,?,?)')
            .bind(payId, m.userId, m.listingId, m.action, amountPaid, s.payment_intent, Date.now()).run();
        }
      }
      return json({ received: true });
    }

    return err('Not found.', 404);
  } catch (e) {
    return err('Server error: ' + e.message, 500);
  }
}
