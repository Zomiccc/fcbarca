require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const webpush = require('web-push');
const { readDb, writeDb, initDb, isPgMode, reseedFromJson } = require('./lib/db');
const { sendJoinConfirmation, sendPaymentReceipt, sendMemberAuthCode } = require('./lib/mailer');
const { buildFixturesRouter } = require('./src/routes/fixtures.route');
const { startFixtureSync } = require('./src/jobs/fixtureSync.job');
const { getCachedFixtures, setMatchHidden, getHiddenMatchIds } = require('./src/services/fixture.service');
const predictor = require('./lib/predictor');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const IS_PROD = process.env.NODE_ENV === 'production';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_PAYMENT_LINK_ADULT = process.env.STRIPE_PAYMENT_LINK_ADULT || '';
const STRIPE_PAYMENT_LINK_KIDS = process.env.STRIPE_PAYMENT_LINK_KIDS || '';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

if (!process.env.JWT_SECRET) {
  console.warn('[warn] JWT_SECRET not set in .env — using a random secret for this process only. ' +
    'Admin sessions will be invalidated every time the server restarts. Set JWT_SECRET in .env for production.');
}
if (STRIPE_PAYMENT_LINK_ADULT || STRIPE_PAYMENT_LINK_KIDS) {
  console.log('[info] STRIPE_PAYMENT_LINK_* set — using simple redirect mode for payments.');
} else if (!stripe) {
  console.warn('[warn] STRIPE_SECRET_KEY not set — the Join Us payment flow will save submissions but ' +
    'cannot create real checkout sessions until you add a Stripe key to .env');
}

// ---------------------------- Web Push (admin phone notifications) ----------------------------
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';
const PUSH_ENABLED = Boolean(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY);
if (PUSH_ENABLED) {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
} else {
  console.warn('[warn] VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY not set — admin phone notifications are disabled.');
}

/** Push a notification to every device the admin has enabled notifications on. */
async function notifyAdminDevices(payload) {
  if (!PUSH_ENABLED) return;
  const db = readDb();
  const subs = db.pushSubscriptions || [];
  if (!subs.length) return;
  const body = JSON.stringify(payload);
  const stale = [];
  await Promise.all(subs.map(async (sub) => {
    try {
      await webpush.sendNotification(sub.subscription, body);
    } catch (err) {
      // 404/410 = the browser unsubscribed or the subscription expired — clean it up.
      if (err.statusCode === 404 || err.statusCode === 410) stale.push(sub.endpoint);
      else console.warn('[push] send failed:', err.message);
    }
  }));
  if (stale.length) {
    await writeDb((d) => {
      d.pushSubscriptions = (d.pushSubscriptions || []).filter((s) => !stale.includes(s.endpoint));
      return d;
    });
  }
}

// ---------- Stripe webhook needs the RAW body, so register it before express.json() ----------
// Note: When using STRIPE_PAYMENT_LINK_* mode, webhooks are not used. The payment link
// handles payment confirmation directly through Stripe's hosted checkout page.
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (STRIPE_PAYMENT_LINK_ADULT || STRIPE_PAYMENT_LINK_KIDS) {
    console.warn('[webhook] Payment link mode is active — webhooks are not used in this mode.');
    return res.status(200).send('ignored (payment link mode)');
  }
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    console.warn('[webhook] Received event but Stripe/webhook secret not configured — ignoring.');
    return res.status(200).send('ignored (not configured)');
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('[webhook] Signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const memberId = session.client_reference_id;
    writeDb((db) => {
      const member = db.members.find((m) => m.id === memberId);
      if (member) {
        member.status = 'paid';
        member.stripeSessionId = session.id;
        member.paidAt = new Date().toISOString();
      } else {
        console.warn('[webhook] checkout.session.completed for unknown member id:', memberId);
      }
      return db;
    })
      .then((updated) => {
        const member = updated.members.find((m) => m.id === memberId);
        if (member) {
          // Payment receipt — best-effort, non-blocking.
          sendPaymentReceipt(member).catch((err) => {
            console.error('[mailer] failed to send payment receipt:', err.message);
          });
        }
      })
      .catch((err) => console.error('[webhook] failed to update member:', err));
  }

  res.json({ received: true });
});

app.use(express.json());
app.use(cookieParser());

// ---------------------------- Auth helpers ----------------------------
function signSession(username) {
  return jwt.sign({ username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
}
function requireAdmin(req, res, next) {
  const token = req.cookies.pbi_admin_session;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie('pbi_admin_session');
    return res.status(401).json({ error: 'Session expired, please log in again' });
  }
}
function cookieOptions() {
  return { httpOnly: true, sameSite: 'lax', secure: IS_PROD, maxAge: 8 * 60 * 60 * 1000 };
}

// ---------------------------- Member auth helpers ----------------------------
// Members are a separate audience from the admin: their session is a different
// cookie with a different role claim, so an admin token can never be used as a
// member token (or vice versa).
const MEMBER_COOKIE = 'pbi_member_session';

function signMemberSession(memberId) {
  return jwt.sign({ memberId, role: 'member' }, JWT_SECRET, { expiresIn: '30d' });
}
function memberCookieOptions() {
  return { httpOnly: true, sameSite: 'lax', secure: IS_PROD, maxAge: 30 * 24 * 60 * 60 * 1000 };
}

/**
 * Guard for member-only routes. Re-reads the member on every request so that a
 * membership that lapses (status flipped off 'paid') immediately loses access,
 * even if they still hold a valid cookie.
 */
function requireMember(req, res, next) {
  const token = req.cookies[MEMBER_COOKIE];
  if (!token) return res.status(401).json({ error: 'Please log in to continue' });

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    res.clearCookie(MEMBER_COOKIE);
    return res.status(401).json({ error: 'Your session expired — please log in again' });
  }
  if (payload.role !== 'member') return res.status(401).json({ error: 'Not a member session' });

  const member = readDb().members.find((m) => m.id === payload.memberId);
  if (!member) {
    res.clearCookie(MEMBER_COOKIE);
    return res.status(401).json({ error: 'Membership not found' });
  }
  if (member.status !== 'paid') {
    return res.status(403).json({ error: 'Only paid members can access the Match Predictions' });
  }
  req.member = member;
  next();
}

function publicMember(member) {
  return {
    id: member.id,
    firstName: member.firstName,
    lastName: member.lastName,
    email: member.email,
    membershipType: member.membershipType,
  };
}

// ---------------------------- Fixtures (Football-Data.org, cached) ----------------------------
// Public + admin fixture endpoints. The scheduler keeps data/fixtures.json
// fresh (12h normally, 5 min on match day) — visitors never hit Football-Data.
app.use(buildFixturesRouter(requireAdmin));

// ---------------------------- Admin auth API ----------------------------
const loginAttempts = new Map(); // ip -> {count, resetAt}  (basic brute-force throttle)
app.post('/api/admin/login', async (req, res) => {
  const ip = req.ip;
  const now = Date.now();
  const attempt = loginAttempts.get(ip);
  if (attempt && attempt.count >= 8 && now < attempt.resetAt) {
    return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' });
  }

  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

  const db = readDb();
  const ok = username === db.admin.username && (await bcrypt.compare(password, db.admin.passwordHash));

  if (!ok) {
    const next = { count: (attempt?.count || 0) + 1, resetAt: now + 5 * 60 * 1000 };
    loginAttempts.set(ip, next);
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  loginAttempts.delete(ip);

  res.cookie('pbi_admin_session', signSession(username), cookieOptions());
  res.json({ ok: true, username });
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('pbi_admin_session');
  res.json({ ok: true });
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.json({ username: req.admin.username });
});

app.post('/api/admin/change-password', requireAdmin, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  const db = readDb();
  const ok = await bcrypt.compare(currentPassword || '', db.admin.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });

  const newHash = await bcrypt.hash(newPassword, 10);
  await writeDb((d) => { d.admin.passwordHash = newHash; return d; });
  res.json({ ok: true });
});

// ---------------------------- Instagram feed (Legacy SnapWidget embed - DEPRECATED) ----------------------------
// NOTE: The Media page now uses the self-hosted media gallery above instead of
// any third-party widget. These endpoints are kept only for backward compatibility.
app.get('/api/instagram-embed', (req, res) => {
  const db = readDb();
  res.json({ embedCode: db.instagramEmbedCode || '' });
});

app.put('/api/admin/instagram-embed', requireAdmin, async (req, res) => {
  const { embedCode } = req.body || {};
  if (typeof embedCode !== 'string') return res.status(400).json({ error: 'embedCode must be a string' });
  if (embedCode.length > 5000) return res.status(400).json({ error: 'Embed code is unexpectedly long — please double check what you pasted.' });
  const updated = await writeDb((db) => { db.instagramEmbedCode = embedCode.trim(); return db; });
  res.json({ embedCode: updated.instagramEmbedCode });
});

// ---------------------------- Pricing ----------------------------
// Public: anyone (the Join Us page) can read current prices.
app.get('/api/pricing', (req, res) => {
  const db = readDb();
  res.json(db.pricing);
});

// Admin-only: change prices. This is what makes the Stripe checkout amount
// "live" — join.html always asks the server for the current price at the
// moment someone submits the form, it never hardcodes an amount.
app.put('/api/admin/pricing', requireAdmin, async (req, res) => {
  const { adult, kids, currency } = req.body || {};
  if (adult == null || kids == null) return res.status(400).json({ error: 'adult and kids prices are required' });
  const adultNum = Number(adult);
  const kidsNum = Number(kids);
  if (!Number.isFinite(adultNum) || adultNum <= 0 || !Number.isFinite(kidsNum) || kidsNum <= 0) {
    return res.status(400).json({ error: 'Prices must be positive numbers' });
  }
  const updated = await writeDb((db) => {
    db.pricing = { adult: adultNum, kids: kidsNum, currency: currency || db.pricing.currency || 'PKR' };
    return db;
  });
  res.json(updated.pricing);
});

// ---------------------------- Membership submission + Stripe Checkout ----------------------------
const VALID_TYPES = ['adult', 'kids'];

app.post('/api/join', async (req, res) => {
  const b = req.body || {};
  const required = ['firstName', 'lastName', 'contactNumber', 'country', 'email', 'membershipType'];
  for (const field of required) {
    if (!b[field] || String(b[field]).trim() === '') {
      return res.status(400).json({ error: `Missing required field: ${field}` });
    }
  }
  if (!VALID_TYPES.includes(b.membershipType)) {
    return res.status(400).json({ error: 'membershipType must be "adult" or "kids"' });
  }
  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.email);
  if (!emailOk) return res.status(400).json({ error: 'Please provide a valid email address' });
  if (b.membershipType === 'kids' && (!b.childName || !b.childDob)) {
    return res.status(400).json({ error: 'Child full name and date of birth are required for a kids membership' });
  }
  if (!b.agreedToStatutes) {
    return res.status(400).json({ error: 'You must agree to the Statutes and Privacy Notice' });
  }

  const db = readDb();
  const price = db.pricing[b.membershipType];
  const memberId = crypto.randomUUID();

  const member = {
    id: memberId,
    firstName: b.firstName.trim(),
    lastName: b.lastName.trim(),
    contactNumber: b.contactNumber.trim(),
    country: b.country.trim(),
    email: b.email.trim(),
    membershipType: b.membershipType,
    childName: b.membershipType === 'kids' ? b.childName.trim() : null,
    childDob: b.membershipType === 'kids' ? b.childDob : null,
    amount: price,
    currency: db.pricing.currency,
    status: 'pending',
    stripeSessionId: null,
    createdAt: new Date().toISOString(),
    paidAt: null,
  };

  await writeDb((d) => { d.members.push(member); return d; });

  // Send the applicant a confirmation email (best-effort; never block the
  // response on mail delivery. If SendGrid is misconfigured or the sender
  // isn't verified yet, the join still succeeds.)
  sendJoinConfirmation(member).catch((err) => {
    console.error('[mailer] failed to send join confirmation:', err.message);
  });

  // Payment Link mode (simple redirect) - takes priority over full Stripe integration
  if (STRIPE_PAYMENT_LINK_ADULT || STRIPE_PAYMENT_LINK_KIDS) {
    const paymentLink = b.membershipType === 'adult' ? STRIPE_PAYMENT_LINK_ADULT : STRIPE_PAYMENT_LINK_KIDS;
    if (paymentLink) {
      return res.json({ ok: true, memberId, checkoutUrl: paymentLink });
    }
    // If the specific membership type link is not set, fall through to warning
    console.warn(`[stripe] Payment link not configured for membership type: ${b.membershipType}`);
  }

  // Full Stripe Checkout session mode (legacy - can be re-enabled by removing STRIPE_PAYMENT_LINK_*)
  if (!stripe) {
    return res.status(200).json({
      ok: true,
      memberId,
      warning: 'Submission saved, but online payment is not configured yet on this server ' +
        '(missing STRIPE_SECRET_KEY or STRIPE_PAYMENT_LINK_*). An admin needs to add it, or mark this member as paid manually.',
      checkoutUrl: null,
    });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      client_reference_id: memberId,
      customer_email: member.email,
      line_items: [
        {
          price_data: {
            currency: (db.pricing.currency || 'PKR').toLowerCase(),
            product_data: {
              name: `Penya Blaugrana Islamabad — ${b.membershipType === 'adult' ? 'Adult' : 'Kids (Under 16)'} Membership`,
            },
            unit_amount: Math.round(price * 100), // Stripe expects the smallest currency unit
          },
          quantity: 1,
        },
      ],
      metadata: { memberId, membershipType: b.membershipType },
      success_url: `${PUBLIC_BASE_URL}/join-success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${PUBLIC_BASE_URL}/join.html?canceled=1`,
    });

    await writeDb((d) => {
      const m = d.members.find((x) => x.id === memberId);
      if (m) m.stripeSessionId = session.id;
      return d;
    });

    res.json({ ok: true, memberId, checkoutUrl: session.url });
  } catch (err) {
    console.error('[stripe] failed to create checkout session:', err.message);
    res.status(502).json({
      ok: true,
      memberId,
      warning: 'Submission saved, but we could not start the Stripe checkout (' + err.message + '). ' +
        'Please contact the club or try again shortly.',
      checkoutUrl: null,
    });
  }
});

// Confirms a session client-side on the success page (belt-and-braces on top of the webhook,
// since webhooks can be delayed by a few seconds).
app.get('/api/checkout-session/:id', async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });
  try {
    const session = await stripe.checkout.sessions.retrieve(req.params.id);
    res.json({ status: session.payment_status, memberId: session.client_reference_id });
  } catch (err) {
    res.status(404).json({ error: 'Session not found' });
  }
});

// ---------------------------- Admin: members ----------------------------
app.get('/api/admin/members', requireAdmin, (req, res) => {
  const db = readDb();
  const { status, type, q } = req.query;
  let members = [...db.members].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  if (status) members = members.filter((m) => m.status === status);
  if (type) members = members.filter((m) => m.membershipType === type);
  if (q) {
    const needle = String(q).toLowerCase();
    members = members.filter((m) =>
      `${m.firstName} ${m.lastName} ${m.email} ${m.country}`.toLowerCase().includes(needle));
  }
  res.json({ members, total: db.members.length });
});

app.post('/api/admin/members/:id/mark-paid', requireAdmin, async (req, res) => {
  const updated = await writeDb((db) => {
    const m = db.members.find((x) => x.id === req.params.id);
    if (m) { m.status = 'paid'; m.paidAt = new Date().toISOString(); m.manualOverride = true; }
    return db;
  });
  const member = updated.members.find((x) => x.id === req.params.id);
  if (!member) return res.status(404).json({ error: 'Member not found' });

  console.log('[mailer] Sending payment receipt to:', member.email, 'for member:', member.firstName, member.lastName);

  // Send the receipt when an admin manually marks a member as paid too
  // (best-effort, non-blocking).
  sendPaymentReceipt(member).catch((err) => {
    console.error('[mailer] failed to send payment receipt (manual):', err.message);
  });

  res.json({ ok: true, member });
});

// Manually add a member from the admin dashboard.
// Creates a paid member with a predictor password so they can log in
// to the Match Predictions page immediately.
app.post('/api/admin/members/add', requireAdmin, async (req, res) => {
  const { firstName, lastName, email, membershipType, password } = req.body || {};
  if (!email || !firstName) {
    return res.status(400).json({ error: 'First name and email are required' });
  }
  const normalizedEmail = String(email).trim().toLowerCase();
  if (String(password || '').length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  const db = readDb();
  if (db.members.find((m) => m.email.toLowerCase() === normalizedEmail)) {
    return res.status(409).json({ error: 'A member with that email already exists' });
  }
  const pricing = db.pricing || { adult: 3000, kids: 1000, currency: 'PKR' };
  const type = membershipType === 'kids' ? 'kids' : 'adult';
  const passwordHash = await bcrypt.hash(String(password), 10);
  const member = {
    id: crypto.randomUUID(),
    firstName: String(firstName).trim(),
    lastName: String(lastName || '').trim(),
    contactNumber: '',
    country: 'Pakistan',
    email: normalizedEmail,
    membershipType: type,
    childName: null,
    childDob: null,
    amount: type === 'kids' ? pricing.kids : pricing.adult,
    currency: pricing.currency,
    status: 'paid',
    stripeSessionId: null,
    createdAt: new Date().toISOString(),
    paidAt: new Date().toISOString(),
    manualOverride: true,
    passwordHash,
  };
  await writeDb((d) => { d.members.push(member); return d; });
  res.json({ ok: true, member: { ...member, passwordHash: undefined } });
});

// Restore predictions that were lost due to a DB reseed.
// Bypasses the deadline check — used for disaster recovery only.
// Accepts an array of { memberId, fixtureId, homeGoals, awayGoals } objects.
// Skips duplicates (same memberId + fixtureId already in DB).
app.post('/api/admin/predictions/restore', requireAdmin, async (req, res) => {
  const { predictions } = req.body || {};
  if (!Array.isArray(predictions) || !predictions.length) {
    return res.status(400).json({ error: 'predictions array is required' });
  }
  let restored = 0;
  let skipped = 0;
  await writeDb((db) => {
    const existing = new Set(
      db.predictions.map((p) => `${p.memberId}:${p.fixtureId}`)
    );
    for (const p of predictions) {
      const key = `${p.memberId}:${p.fixtureId}`;
      if (existing.has(key)) {
        skipped++;
        continue;
      }
      db.predictions.push({
        memberId: String(p.memberId),
        fixtureId: Number(p.fixtureId),
        homeGoals: Number(p.homeGoals),
        awayGoals: Number(p.awayGoals),
        createdAt: p.createdAt || new Date().toISOString(),
      });
      existing.add(key);
      restored++;
    }
    return db;
  });
  res.json({ ok: true, restored, skipped });
});

// Diagnostic: check if the server is using PostgreSQL or JSON fallback.
// Helps debug data loss issues on Render.
app.get('/api/admin/db-status', requireAdmin, async (req, res) => {
  const db = readDb();
  res.json({
    pgMode: isPgMode(),
    databaseUrlSet: Boolean(process.env.DATABASE_URL),
    memberCount: (db.members || []).length,
    predictionCount: (db.predictions || []).length,
    mediaPostCount: (db.mediaPosts || []).length,
  });
});

// Force reseed: drops the PostgreSQL app_state row and reseeds from db.json.
// Use this when the PostgreSQL database is empty but db.json has data.
app.post('/api/admin/db/reseed', requireAdmin, async (req, res) => {
  if (!isPgMode()) {
    return res.status(400).json({ error: 'Not in PostgreSQL mode — reseed is only for PG. Data is already from db.json.' });
  }
  try {
    const db = await reseedFromJson();
    res.json({
      ok: true,
      memberCount: (db.members || []).length,
      predictionCount: (db.predictions || []).length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/members/:id', requireAdmin, async (req, res) => {
  await writeDb((db) => {
    db.members = db.members.filter((x) => x.id !== req.params.id);
    return db;
  });
  res.json({ ok: true });
});

app.get('/api/admin/members/export.csv', requireAdmin, (req, res) => {
  const db = readDb();
  const cols = ['id', 'firstName', 'lastName', 'email', 'contactNumber', 'country',
    'membershipType', 'childName', 'childDob', 'amount', 'currency', 'status', 'createdAt', 'paidAt'];
  const escape = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = [cols.join(',')].concat(
    db.members.map((m) => cols.map((c) => escape(m[c])).join(','))
  );
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="pbi-members.csv"');
  res.send(rows.join('\n'));
});

app.get('/api/admin/dashboard-stats', requireAdmin, (req, res) => {
  const db = readDb();
  const total = db.members.length;
  const paid = db.members.filter((m) => m.status === 'paid').length;
  const pending = total - paid;
  const adults = db.members.filter((m) => m.membershipType === 'adult').length;
  const kids = db.members.filter((m) => m.membershipType === 'kids').length;
  const revenue = db.members.filter((m) => m.status === 'paid').reduce((sum, m) => sum + (m.amount || 0), 0);
  res.json({ total, paid, pending, adults, kids, revenue, currency: db.pricing.currency });
});

/* ==========================================================================
   MEMBER AUTH (Match Predictions)
   Paid members set a password using a 6-digit code emailed to the address on
   their membership record. That email round-trip is what proves ownership —
   without it, anyone knowing a member's email could claim their account.
   ========================================================================== */
const CODE_TTL_MINUTES = 15;
const memberAuthAttempts = new Map(); // email -> {count, resetAt}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}
function findPaidMemberByEmail(db, email) {
  const needle = normalizeEmail(email);
  return db.members.find((m) => normalizeEmail(m.email) === needle && m.status === 'paid');
}
function throttled(key, max = 8, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  const entry = memberAuthAttempts.get(key);
  if (entry && entry.count >= max && now < entry.resetAt) return true;
  memberAuthAttempts.set(key, {
    count: entry && now < entry.resetAt ? entry.count + 1 : 1,
    resetAt: entry && now < entry.resetAt ? entry.resetAt : now + windowMs,
  });
  return false;
}

// Ask for a code to set or reset a password.
// Always answers 200 so this endpoint can't be used to discover which emails
// belong to paid members.
app.post('/api/member/request-code', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const genericOk = {
    ok: true,
    message: 'If that email belongs to a paid member, a 6-digit code is on its way.',
  };
  if (!email) return res.status(400).json({ error: 'Email is required' });
  if (throttled(`code:${email}`)) {
    return res.status(429).json({ error: 'Too many requests. Please try again in a few minutes.' });
  }

  const member = findPaidMemberByEmail(readDb(), email);
  if (!member) return res.json(genericOk);

  const code = String(crypto.randomInt(100000, 1000000));
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000).toISOString();

  await writeDb((db) => {
    // One live code per member: drop any previous ones plus anything expired.
    db.memberAuthCodes = (db.memberAuthCodes || []).filter(
      (c) => c.memberId !== member.id && new Date(c.expiresAt) > new Date(),
    );
    db.memberAuthCodes.push({ memberId: member.id, codeHash, expiresAt, used: false });
    return db;
  });

  sendMemberAuthCode(member, code, CODE_TTL_MINUTES).catch((err) => {
    console.error('[mailer] failed to send member auth code:', err.message);
  });
  res.json(genericOk);
});

// Redeem the code and set a password. Logs the member straight in.
app.post('/api/member/set-password', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const code = String(req.body?.code || '').trim();
  const password = String(req.body?.password || '');

  if (!email || !code || !password) {
    return res.status(400).json({ error: 'Email, code and new password are all required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (throttled(`set:${email}`)) {
    return res.status(429).json({ error: 'Too many attempts. Please try again in a few minutes.' });
  }

  const db = readDb();
  const member = findPaidMemberByEmail(db, email);
  const invalid = { error: 'That code is invalid or has expired. Please request a new one.' };
  if (!member) return res.status(400).json(invalid);

  const entry = (db.memberAuthCodes || []).find(
    (c) => c.memberId === member.id && !c.used && new Date(c.expiresAt) > new Date(),
  );
  if (!entry) return res.status(400).json(invalid);
  if (!(await bcrypt.compare(code, entry.codeHash))) return res.status(400).json(invalid);

  const passwordHash = await bcrypt.hash(password, 10);
  await writeDb((d) => {
    const m = d.members.find((x) => x.id === member.id);
    if (m) m.passwordHash = passwordHash;
    // Codes are single-use: consume this one and sweep expired ones.
    d.memberAuthCodes = (d.memberAuthCodes || []).filter(
      (c) => c.memberId !== member.id && new Date(c.expiresAt) > new Date(),
    );
    return d;
  });

  memberAuthAttempts.delete(`set:${email}`);
  res.cookie(MEMBER_COOKIE, signMemberSession(member.id), memberCookieOptions());
  res.json({ ok: true, member: publicMember(member) });
});

app.post('/api/member/login', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (throttled(`login:${email}`)) {
    return res.status(429).json({ error: 'Too many attempts. Please try again in a few minutes.' });
  }

  const member = findPaidMemberByEmail(readDb(), email);
  // Same message either way so we don't leak which emails are paid members.
  const invalid = { error: 'Incorrect email or password' };
  if (!member) return res.status(401).json(invalid);
  if (!member.passwordHash) {
    return res.status(409).json({
      error: 'No password set yet for this membership. Request a code to set one.',
      needsPassword: true,
    });
  }
  if (!(await bcrypt.compare(password, member.passwordHash))) return res.status(401).json(invalid);

  memberAuthAttempts.delete(`login:${email}`);
  res.cookie(MEMBER_COOKIE, signMemberSession(member.id), memberCookieOptions());
  res.json({ ok: true, member: publicMember(member) });
});

app.post('/api/member/logout', (req, res) => {
  res.clearCookie(MEMBER_COOKIE);
  res.json({ ok: true });
});

app.get('/api/member/me', requireMember, (req, res) => {
  res.json({ member: publicMember(req.member) });
});

/* ==========================================================================
   Match Predictions
   Rules live in lib/predictor.js. Two guarantees are enforced here:

   - IMMUTABILITY: the only write path refuses to touch an existing prediction.
     There is deliberately no update or delete route anywhere in this app, for
     members OR admin, so a stored prediction can never be altered.
   - PRIVACY: other members' predictions are filtered out server-side until
     that match has kicked off, so they are never sent to the browser early.
   ========================================================================== */
function fixtureMatches() {
  return getCachedFixtures().matches || [];
}

// Needed alongside fixtureMatches() any time we ask predictor.hasFinalScore()
// / scorePrediction() / buildLeaderboard() to score a match — see the
// comment on hasFinalScore() in lib/predictor.js for why.
function fixtureLastSync() {
  return getCachedFixtures().lastSync || null;
}

/* The club runs La Liga and the Champions League as two separate
   competitions — separate prediction sets, separate results, separate league
   tables. They run concurrently, so every member-facing predictions endpoint
   takes ?competition=PD|CL and defaults to La Liga. */
const PREDICTION_COMPETITIONS = ['PD', 'CL'];
function requestedCompetition(req) {
  return PREDICTION_COMPETITIONS.includes(req.query.competition) ? req.query.competition : 'PD';
}

// The prediction table for one competition: its current round, the deadline,
// and the member's own already-locked predictions.
app.get('/api/predictions/window', requireMember, (req, res) => {
  const matches = fixtureMatches();
  const now = new Date();
  const competition = requestedCompetition(req);
  const window = predictor.getPredictionWindow(matches, now, competition);
  const deadline = predictor.getDeadline(matches, now, competition);
  const db = readDb();
  const mine = db.predictions.filter((p) => p.memberId === req.member.id);
  const myByFixture = new Map(mine.map((p) => [String(p.fixtureId), p]));

  res.json({
    competition,
    deadline: deadline ? deadline.toISOString() : null,
    points: predictor.POINTS,
    fixtures: window.map((m) => {
      const existing = myByFixture.get(String(m.id));
      return {
        id: m.id,
        utcDate: m.utcDate,
        competition: m.competition,
        competitionCode: m.competitionCode ?? null,
        competitionEmblem: m.competitionEmblem,
        matchday: m.matchday ?? null,
        homeTeam: m.homeTeam,
        homeCrest: m.homeCrest,
        awayTeam: m.awayTeam,
        awayCrest: m.awayCrest,
        // A fixture is only editable if the member has no prediction for it yet.
        locked: Boolean(existing),
        myPrediction: existing
          ? { homeGoals: existing.homeGoals, awayGoals: existing.awayGoals }
          : null,
      };
    }),
  });
});

// Submit predictions for the whole set at once. Append-only.
app.post('/api/predictions', requireMember, async (req, res) => {
  const submitted = Array.isArray(req.body?.predictions) ? req.body.predictions : null;
  if (!submitted || !submitted.length) {
    return res.status(400).json({ error: 'No predictions submitted' });
  }

  const matches = fixtureMatches();
  const now = new Date();

  // Both competitions are open for predictions at the same time, each with
  // its own current round and its own deadline, so a submission is validated
  // against whichever competition the fixture actually belongs to.
  const openSets = PREDICTION_COMPETITIONS.map((code) => {
    const window = predictor.getPredictionWindow(matches, now, code);
    return {
      code,
      byId: new Map(window.map((m) => [String(m.id), m])),
      deadline: window.length ? new Date(window[0].utcDate) : null,
    };
  });
  if (!openSets.some((s) => s.byId.size)) {
    return res.status(409).json({ error: 'There are no upcoming fixtures to predict right now.' });
  }
  const findOpenFixture = (fixtureId) => {
    for (const set of openSets) {
      const match = set.byId.get(fixtureId);
      if (match) return { match, deadline: set.deadline };
    }
    return null;
  };

  const existing = readDb().predictions;
  const alreadyPredicted = new Set(
    existing.filter((p) => p.memberId === req.member.id).map((p) => String(p.fixtureId)),
  );

  const toInsert = [];
  const seen = new Set();
  for (const row of submitted) {
    const fixtureId = String(row?.fixtureId ?? '');
    const homeGoals = Number(row?.homeGoals);
    const awayGoals = Number(row?.awayGoals);

    const open = findOpenFixture(fixtureId);
    if (!open) {
      return res.status(400).json({ error: 'One of those matches is not open for predictions.' });
    }
    const { match, deadline } = open;
    if (deadline && now >= deadline) {
      return res.status(409).json({
        error: 'Predictions are closed — the first match of this set has already kicked off.',
      });
    }
    if (seen.has(fixtureId)) {
      return res.status(400).json({ error: 'Duplicate prediction for the same match.' });
    }
    seen.add(fixtureId);

    // Immutability: never overwrite. Skip anything already locked in so a
    // resubmission of the page can add the new fixtures without error.
    if (alreadyPredicted.has(fixtureId)) continue;

    for (const goals of [homeGoals, awayGoals]) {
      if (!Number.isInteger(goals) || goals < 0 || goals > 20) {
        return res.status(400).json({ error: 'Scores must be whole numbers between 0 and 20.' });
      }
    }
    if (predictor.hasKickedOff(match, now)) {
      return res.status(409).json({ error: `${match.homeTeam} v ${match.awayTeam} has already kicked off.` });
    }

    toInsert.push({
      id: crypto.randomUUID(),
      memberId: req.member.id,
      // Snapshot the name at prediction time so match history still shows a
      // real name even if this member is later deleted from the club roster.
      memberName: `${req.member.firstName} ${req.member.lastName}`.trim(),
      fixtureId: match.id,
      homeGoals,
      awayGoals,
      createdAt: new Date().toISOString(),
    });
  }

  if (!toInsert.length) {
    return res.status(409).json({
      error: 'Those predictions are already locked in and cannot be changed.',
    });
  }

  await writeDb((db) => {
    // Re-check inside the write lock so two concurrent submits can't both slip
    // a prediction in for the same fixture.
    const locked = new Set(
      db.predictions.filter((p) => p.memberId === req.member.id).map((p) => String(p.fixtureId)),
    );
    for (const row of toInsert) {
      if (!locked.has(String(row.fixtureId))) db.predictions.push(row);
    }
    return db;
  });

  res.json({ ok: true, saved: toInsert.length });
});

// The member's own predictions, with points once matches finish.
app.get('/api/predictions/me', requireMember, (req, res) => {
  const matches = fixtureMatches();
  const lastSync = fixtureLastSync();
  const competition = requestedCompetition(req);
  const matchById = new Map(matches.map((m) => [String(m.id), m]));
  const mine = readDb()
    .predictions.filter((p) => p.memberId === req.member.id)
    .filter((p) => matchById.get(String(p.fixtureId))?.competitionCode === competition)
    .map((p) => {
      const match = matchById.get(String(p.fixtureId));
      const finished = predictor.hasFinalScore(match, lastSync);
      const points = finished ? predictor.scorePrediction(p, match, lastSync) : null;
      return {
        fixtureId: p.fixtureId,
        homeTeam: match?.homeTeam || 'Unknown',
        awayTeam: match?.awayTeam || 'Unknown',
        utcDate: match?.utcDate || null,
        homeGoals: p.homeGoals,
        awayGoals: p.awayGoals,
        actual: finished ? { home: match.score.home, away: match.score.away } : null,
        points,
        outcome: points === null ? null : predictor.scoreLabel(points),
        createdAt: p.createdAt,
      };
    })
    .sort((a, b) => new Date(a.utcDate || 0) - new Date(b.utcDate || 0));

  const total = mine.reduce((sum, p) => sum + (p.points || 0), 0);
  res.json({ competition, predictions: mine, totalPoints: total });
});

// Everyone's predictions — but ONLY for matches that have already kicked off.
// The filter is here, server-side, so unstarted predictions never leave the box.
app.get('/api/predictions/all', requireMember, (req, res) => {
  const db = readDb();
  const now = new Date();
  const matches = fixtureMatches();
  const lastSync = fixtureLastSync();
  const competition = requestedCompetition(req);
  const hiddenIds = getHiddenMatchIds(); // display-only filter — never touches scoring
  const matchById = new Map(matches.map((m) => [String(m.id), m]));
  const nameById = new Map(
    db.members.map((m) => [m.id, `${m.firstName} ${m.lastName}`.trim()]),
  );
  // Names the admin manually re-attached to a deleted member's old
  // predictions — see /api/admin/predictions/orphaned.
  const restoredNameById = new Map(
    Object.entries(db.deletedMemberNames || {}).map(([id, r]) => [id, `${r.firstName} ${r.lastName}`.trim()]),
  );

  const revealed = matches
    .filter((m) => m.competitionCode === competition)
    .filter((m) => predictor.hasKickedOff(m, now) && !hiddenIds.has(String(m.id)))
    .sort((a, b) => new Date(b.utcDate) - new Date(a.utcDate))
    .map((match) => {
      const finished = predictor.hasFinalScore(match, lastSync);
      // A match that has kicked off but isn't finished yet can still have a
      // running score from the API (it updates score.fullTime live during
      // play) — show that as "LIVE" rather than a bare "In progress" label.
      const live =
        !finished &&
        ['IN_PLAY', 'PAUSED'].includes(match.status) &&
        Number.isInteger(match.score?.home) &&
        Number.isInteger(match.score?.away)
          ? { home: match.score.home, away: match.score.away }
          : null;
      const rows = db.predictions
        .filter((p) => String(p.fixtureId) === String(match.id))
        // Prefer the name snapshotted when the prediction was made — it
        // survives the member later being deleted. Older predictions made
        // before that snapshot existed fall back to a live lookup, then to
        // any name the admin has manually restored. If none of those
        // resolve, skip the row entirely rather than showing a
        // "Former member" placeholder — same as the leaderboard already does.
        .map((p) => ({ p, name: p.memberName || nameById.get(p.memberId) || restoredNameById.get(p.memberId) }))
        .filter(({ name }) => Boolean(name))
        .map(({ p, name }) => {
          const points = finished ? predictor.scorePrediction(p, match, lastSync) : null;
          return {
            member: name,
            isMe: p.memberId === req.member.id,
            homeGoals: p.homeGoals,
            awayGoals: p.awayGoals,
            points,
            outcome: points === null ? null : predictor.scoreLabel(points),
          };
        })
        .sort((a, b) => (b.points || 0) - (a.points || 0) || a.member.localeCompare(b.member));

      return {
        fixtureId: match.id,
        utcDate: match.utcDate,
        homeTeam: match.homeTeam,
        homeCrest: match.homeCrest,
        awayTeam: match.awayTeam,
        awayCrest: match.awayCrest,
        status: match.status,
        matchday: match.matchday,
        competition: match.competition,
        actual: finished ? { home: match.score.home, away: match.score.away } : null,
        live,
        predictions: rows,
      };
    })
    .filter((m) => m.predictions.length);

  res.json({ competition, matches: revealed });
});

app.get('/api/predictions/leaderboard', requireMember, (req, res) => {
  const db = readDb();
  const currentMembers = db.members.filter((m) => m.status === 'paid');
  const competitionCode = requestedCompetition(req);
  const table = predictor.buildLeaderboard(
    db.predictions,
    currentMembers,
    fixtureMatches(),
    fixtureLastSync(),
    competitionCode,
  );
  res.json({
    leaderboard: table.map((row) => ({ ...row, isMe: row.memberId === req.member.id })),
    points: predictor.POINTS,
    competition: competitionCode,
  });
});

// ---------------------------- Admin: predictions results visibility ----------------------------
// Lets the admin shorten the member-facing "results" list by hiding individual
// finished matches from display. This is purely cosmetic: hidden matches keep
// their stored predictions and final score, buildLeaderboard() always runs
// against the full, unfiltered match list, so nobody's total points change.

// GET /api/admin/predictions/matches — every match with at least one prediction,
// most recent first, with its current hidden/visible state.
app.get('/api/admin/predictions/matches', requireAdmin, (req, res) => {
  const db = readDb();
  const matches = fixtureMatches();
  const lastSync = fixtureLastSync();
  const hiddenIds = getHiddenMatchIds();
  const predictionCounts = new Map();
  for (const p of db.predictions || []) {
    const key = String(p.fixtureId);
    predictionCounts.set(key, (predictionCounts.get(key) || 0) + 1);
  }

  const rows = matches
    .filter((m) => predictionCounts.has(String(m.id)))
    .sort((a, b) => new Date(b.utcDate) - new Date(a.utcDate))
    .map((m) => ({
      fixtureId: m.id,
      utcDate: m.utcDate,
      homeTeam: m.homeTeam,
      awayTeam: m.awayTeam,
      status: m.status,
      matchday: m.matchday,
      competition: m.competition,
      actual: predictor.hasFinalScore(m, lastSync) ? { home: m.score.home, away: m.score.away } : null,
      predictionsCount: predictionCounts.get(String(m.id)) || 0,
      hidden: hiddenIds.has(String(m.id)),
    }));

  res.json({ matches: rows });
});

// POST /api/admin/predictions/matches/:id/hide — remove a match from the
// public results list without touching its predictions or anyone's points.
app.post('/api/admin/predictions/matches/:id/hide', requireAdmin, (req, res) => {
  const hidden = setMatchHidden(req.params.id, true);
  res.json({ ok: true, hiddenMatches: hidden });
});

// POST /api/admin/predictions/matches/:id/unhide — restore a previously hidden match.
app.post('/api/admin/predictions/matches/:id/unhide', requireAdmin, (req, res) => {
  const hidden = setMatchHidden(req.params.id, false);
  res.json({ ok: true, hiddenMatches: hidden });
});

// ---------------------------- Admin: orphaned predictions ----------------------------
// When a member is deleted, only their `members` row goes away — their
// predictions and chat history stay forever (predictions are append-only by
// design; chat is never cleaned up on member deletion). This surfaces every
// prediction whose memberId no longer resolves to a name, grouped by member,
// with any chat history for that same memberId, so the admin can recognize
// who it was and re-attach their name — without resurrecting their account.

// GET /api/admin/predictions/orphaned — grouped by memberId.
app.get('/api/admin/predictions/orphaned', requireAdmin, (req, res) => {
  const db = readDb();
  const matches = fixtureMatches();
  const matchById = new Map(matches.map((m) => [String(m.id), m]));
  const nameById = new Map(db.members.map((m) => [m.id, `${m.firstName} ${m.lastName}`.trim()]));
  const restored = db.deletedMemberNames || {};

  const groups = new Map();
  for (const p of db.predictions || []) {
    if (p.memberName || nameById.get(p.memberId)) continue; // still a resolvable name — not orphaned
    if (!groups.has(p.memberId)) {
      const conv = (db.chatConversations || []).find((c) => c.memberId === p.memberId);
      const r = restored[p.memberId];
      groups.set(p.memberId, {
        memberId: p.memberId,
        restoredName: r ? `${r.firstName} ${r.lastName}`.trim() : null,
        conversationId: conv ? conv.id : null,
        predictions: [],
      });
    }
    const match = matchById.get(String(p.fixtureId));
    groups.get(p.memberId).predictions.push({
      fixtureId: p.fixtureId,
      homeTeam: match ? match.homeTeam : 'Unknown',
      awayTeam: match ? match.awayTeam : 'Unknown',
      utcDate: match ? match.utcDate : null,
      homeGoals: p.homeGoals,
      awayGoals: p.awayGoals,
      createdAt: p.createdAt,
    });
  }

  const result = [...groups.values()].sort((a, b) => {
    const aLatest = Math.max(...a.predictions.map((p) => new Date(p.createdAt).getTime()));
    const bLatest = Math.max(...b.predictions.map((p) => new Date(p.createdAt).getTime()));
    return bLatest - aLatest;
  });

  res.json({ groups: result });
});

// POST /api/admin/predictions/orphaned/:memberId/restore — attach a name.
// Body: { firstName, lastName }. Does NOT touch `members` — this can never
// grant login access or reappear in member management/stats/leaderboard.
app.post('/api/admin/predictions/orphaned/:memberId/restore', requireAdmin, async (req, res) => {
  const { memberId } = req.params;
  const firstName = String(req.body?.firstName || '').trim();
  const lastName = String(req.body?.lastName || '').trim();
  if (!firstName) {
    return res.status(400).json({ error: 'First name is required' });
  }
  await writeDb((d) => {
    d.deletedMemberNames = d.deletedMemberNames || {};
    d.deletedMemberNames[memberId] = { firstName, lastName, restoredAt: new Date().toISOString() };
    return d;
  });
  res.json({ ok: true, name: `${firstName} ${lastName}`.trim() });
});

// DELETE /api/admin/predictions/orphaned/:memberId/restore — undo a restore.
app.delete('/api/admin/predictions/orphaned/:memberId/restore', requireAdmin, async (req, res) => {
  const { memberId } = req.params;
  await writeDb((d) => {
    if (d.deletedMemberNames) delete d.deletedMemberNames[memberId];
    return d;
  });
  res.json({ ok: true });
});

/* ==========================================================================
   Peyna Assistant — one-to-one member-admin chat with privacy
   Each member has exactly one private conversation thread with the admin.
   Members can only read/write their own conversation.
   Admin sees a conversation list and can select/reply to each member.
   ========================================================================== */

const multer = require('multer');
const chatUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max (stored in DB as base64)
});

// Helper: get or create a conversation for a member
function getOrCreateConversation(db, memberId) {
  let conv = (db.chatConversations || []).find((c) => c.memberId === memberId);
  if (!conv) {
    conv = {
      id: crypto.randomUUID(),
      memberId,
      resolved: false,
      resolvedAt: null,
      resolvedBy: null,
      adminUnreadCount: 0,
      memberUnreadCount: 0,
      createdAt: new Date().toISOString(),
    };
    db.chatConversations = db.chatConversations || [];
    db.chatConversations.push(conv);
  }
  return conv;
}

// Helper: build a replyTo preview from a referenced message
function buildReplyPreview(db, replyToMessageId, conversationId) {
  if (!replyToMessageId) return null;
  const orig = (db.chatMessages || []).find((m) => m.id === replyToMessageId && m.conversationId === conversationId);
  if (!orig) return null;
  let preview = orig.text || '';
  if (orig.voiceNote) preview = '🎤 Voice note';
  else if (orig.attachment) preview = `📎 ${orig.attachment.filename || 'Attachment'}`;
  if (preview.length > 80) preview = preview.slice(0, 77) + '...';
  return {
    messageId: orig.id,
    senderRole: orig.senderRole || 'member',
    preview,
  };
}

/* ---------- Member chat endpoints ---------- */

// GET /api/chat/messages — member gets ONLY their own conversation messages
app.get('/api/chat/messages', requireMember, (req, res) => {
  const db = readDb();
  const memberId = req.member.id;
  const conv = (db.chatConversations || []).find((c) => c.memberId === memberId);
  const memberName = `${req.member.firstName} ${req.member.lastName}`.trim();

  // Member's own conversation messages only — privacy enforced server-side
  const convMessages = (db.chatMessages || [])
    .filter((m) => conv && m.conversationId === conv.id)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .map((m) => {
      const isMe = m.senderId === memberId;
      const isAdmin = m.senderRole === 'admin';
      return {
        id: m.id,
        conversationId: m.conversationId,
        senderId: m.senderId || null,
        senderRole: m.senderRole || 'member',
        senderName: isAdmin ? 'Admin' : memberName,
        isMe,
        isAdmin,
        messageType: m.messageType || 'text',
        text: m.text || '',
        attachment: m.attachment || null,
        voiceNote: m.voiceNote || null,
        replyToMessageId: m.replyToMessageId || null,
        replyTo: buildReplyPreview(db, m.replyToMessageId, conv ? conv.id : null),
        createdAt: m.createdAt,
      };
    });

  const messages = convMessages;

  // Reset member unread count (they're reading now)
  if (conv && conv.memberUnreadCount > 0) {
    writeDb((d) => {
      const c = (d.chatConversations || []).find((x) => x.id === conv.id);
      if (c) c.memberUnreadCount = 0;
      return d;
    });
  }

  res.json({ messages, conversation: conv ? { id: conv.id, resolved: conv.resolved } : null });
});

// GET /api/chat/unread-count — member's unread count, WITHOUT resetting it.
// Used to show a badge on the "Talk to Admin" button even while the chat
// panel is closed (opening the panel/loading messages is what clears it).
app.get('/api/chat/unread-count', requireMember, (req, res) => {
  const db = readDb();
  const conv = (db.chatConversations || []).find((c) => c.memberId === req.member.id);
  res.json({ unreadCount: conv ? (conv.memberUnreadCount || 0) : 0 });
});

// POST /api/chat/messages — member sends a text message in their own conversation
app.post('/api/chat/messages', requireMember, async (req, res) => {
  const { text, replyToMessageId } = req.body || {};
  if (!text || !String(text).trim()) {
    return res.status(400).json({ error: 'Message text is required' });
  }
  if (String(text).length > 2000) {
    return res.status(400).json({ error: 'Message too long (max 2000 characters)' });
  }

  const memberId = req.member.id;
  let msg;
  await writeDb((d) => {
    const conv = getOrCreateConversation(d, memberId);
    // Verify replyTo belongs to this conversation
    let safeReplyTo = null;
    if (replyToMessageId) {
      const orig = (d.chatMessages || []).find((m) => m.id === replyToMessageId && m.conversationId === conv.id);
      if (orig) safeReplyTo = replyToMessageId;
    }
    msg = {
      id: crypto.randomUUID(),
      conversationId: conv.id,
      senderId: memberId,
      senderRole: 'member',
      messageType: 'text',
      text: String(text).trim(),
      replyToMessageId: safeReplyTo,
      createdAt: new Date().toISOString(),
    };
    (d.chatMessages = d.chatMessages || []).push(msg);
    conv.adminUnreadCount = (conv.adminUnreadCount || 0) + 1;
    return d;
  });

  const memberName = `${req.member.firstName} ${req.member.lastName}`.trim();
  notifyAdminDevices({ title: `New message from ${memberName}`, body: msg.text });

  res.json({ ok: true, message: msg });
});

// POST /api/chat/upload — member sends a file/voice note in their own conversation
app.post('/api/chat/upload', requireMember, chatUpload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  const text = (req.body.text || '').trim() || '';
  const isVoice = req.body.voiceNote === 'true';
  const replyToMessageId = req.body.replyToMessageId || null;
  const dataUrl = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
  const memberId = req.member.id;

  let msg;
  await writeDb((d) => {
    const conv = getOrCreateConversation(d, memberId);
    let safeReplyTo = null;
    if (replyToMessageId) {
      const orig = (d.chatMessages || []).find((m) => m.id === replyToMessageId && m.conversationId === conv.id);
      if (orig) safeReplyTo = replyToMessageId;
    }
    msg = {
      id: crypto.randomUUID(),
      conversationId: conv.id,
      senderId: memberId,
      senderRole: 'member',
      messageType: isVoice ? 'voice' : 'attachment',
      text,
      replyToMessageId: safeReplyTo,
      createdAt: new Date().toISOString(),
    };
    if (isVoice) {
      msg.voiceNote = { dataUrl, filename: req.file.originalname, size: req.file.size, mimetype: req.file.mimetype };
    } else {
      msg.attachment = { dataUrl, filename: req.file.originalname, size: req.file.size, mimetype: req.file.mimetype };
    }
    (d.chatMessages = d.chatMessages || []).push(msg);
    conv.adminUnreadCount = (conv.adminUnreadCount || 0) + 1;
    return d;
  });

  const memberName = `${req.member.firstName} ${req.member.lastName}`.trim();
  notifyAdminDevices({
    title: `New message from ${memberName}`,
    body: isVoice ? '🎤 Sent a voice note' : `📎 Sent an attachment: ${req.file.originalname}`,
  });

  res.json({ ok: true, message: msg });
});

/* ---------- Admin chat endpoints ---------- */

// GET /api/admin/chat/conversations — list all conversations with unread/resolved state
app.get('/api/admin/chat/conversations', requireAdmin, (req, res) => {
  const db = readDb();
  const nameById = new Map(db.members.map((m) => [m.id, `${m.firstName} ${m.lastName}`.trim()]));
  const emailById = new Map(db.members.map((m) => [m.id, m.email]));
  const restored = db.deletedMemberNames || {};
  const restoredName = (id) => (restored[id] ? `${restored[id].firstName} ${restored[id].lastName}`.trim() : null);

  const convs = (db.chatConversations || []).map((c) => {
    const lastMsg = (db.chatMessages || [])
      .filter((m) => m.conversationId === c.id)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
    return {
      id: c.id,
      memberId: c.memberId,
      memberName: nameById.get(c.memberId) || restoredName(c.memberId) || 'Former member',
      memberEmail: emailById.get(c.memberId) || null,
      resolved: Boolean(c.resolved),
      resolvedAt: c.resolvedAt || null,
      adminUnreadCount: c.adminUnreadCount || 0,
      lastMessageAt: lastMsg ? lastMsg.createdAt : c.createdAt,
      lastMessagePreview: lastMsg ? (lastMsg.text || (lastMsg.voiceNote ? '🎤 Voice note' : '📎 Attachment')) : null,
    };
  }).sort((a, b) => new Date(b.lastMessageAt) - new Date(a.lastMessageAt));

  res.json({ conversations: convs });
});

// GET /api/admin/chat/messages/:conversationId — admin gets messages for a specific conversation
app.get('/api/admin/chat/messages/:conversationId', requireAdmin, (req, res) => {
  const db = readDb();
  const convId = req.params.conversationId;
  const conv = (db.chatConversations || []).find((c) => c.id === convId);
  if (!conv) {
    return res.status(404).json({ error: 'Conversation not found' });
  }

  const nameById = new Map(db.members.map((m) => [m.id, `${m.firstName} ${m.lastName}`.trim()]));
  const emailById = new Map(db.members.map((m) => [m.id, m.email]));
  const restored = db.deletedMemberNames || {};
  const restoredName = (id) => (restored[id] ? `${restored[id].firstName} ${restored[id].lastName}`.trim() : null);

  const messages = (db.chatMessages || [])
    .filter((m) => m.conversationId === convId)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .map((m) => {
      const isAdmin = m.senderRole === 'admin';
      return {
        id: m.id,
        conversationId: m.conversationId,
        senderId: m.senderId || null,
        senderRole: m.senderRole || 'member',
        senderName: isAdmin ? 'Admin' : (nameById.get(m.senderId) || restoredName(m.senderId) || 'Former member'),
        senderEmail: isAdmin ? null : (emailById.get(m.senderId) || null),
        isAdmin,
        messageType: m.messageType || 'text',
        text: m.text || '',
        attachment: m.attachment || null,
        voiceNote: m.voiceNote || null,
        replyToMessageId: m.replyToMessageId || null,
        replyTo: buildReplyPreview(db, m.replyToMessageId, convId),
        createdAt: m.createdAt,
      };
    });

  // Reset admin unread count for this conversation
  if (conv.adminUnreadCount > 0) {
    writeDb((d) => {
      const c = (d.chatConversations || []).find((x) => x.id === convId);
      if (c) c.adminUnreadCount = 0;
      return d;
    });
  }

  res.json({
    conversation: {
      id: conv.id,
      memberId: conv.memberId,
      memberName: nameById.get(conv.memberId) || restoredName(conv.memberId) || 'Former member',
      memberEmail: emailById.get(conv.memberId) || null,
      resolved: Boolean(conv.resolved),
    },
    messages,
  });
});

// POST /api/admin/chat/reply — admin replies to a specific conversation
app.post('/api/admin/chat/reply', requireAdmin, async (req, res) => {
  const { text, conversationId, replyToMessageId } = req.body || {};
  if (!text || !String(text).trim()) {
    return res.status(400).json({ error: 'Reply text is required' });
  }
  if (String(text).length > 2000) {
    return res.status(400).json({ error: 'Message too long (max 2000 characters)' });
  }
  if (!conversationId) {
    return res.status(400).json({ error: 'conversationId is required' });
  }

  let msg;
  let found = false;
  await writeDb((d) => {
    const conv = (d.chatConversations || []).find((c) => c.id === conversationId);
    if (!conv) return d;
    found = true;

    let safeReplyTo = null;
    if (replyToMessageId) {
      const orig = (d.chatMessages || []).find((m) => m.id === replyToMessageId && m.conversationId === conversationId);
      if (orig) safeReplyTo = replyToMessageId;
    }

    msg = {
      id: crypto.randomUUID(),
      conversationId,
      senderId: null,
      senderRole: 'admin',
      messageType: 'text',
      text: String(text).trim(),
      replyToMessageId: safeReplyTo,
      createdAt: new Date().toISOString(),
    };
    (d.chatMessages = d.chatMessages || []).push(msg);
    conv.memberUnreadCount = (conv.memberUnreadCount || 0) + 1;
    return d;
  });

  if (!found) return res.status(404).json({ error: 'Conversation not found' });
  res.json({ ok: true, message: msg });
});

// POST /api/admin/chat/upload — admin sends a file/voice reply to a conversation
app.post('/api/admin/chat/upload', requireAdmin, chatUpload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  const { conversationId, replyToMessageId } = req.body || {};
  if (!conversationId) {
    return res.status(400).json({ error: 'conversationId is required' });
  }
  const text = (req.body.text || '').trim() || '';
  const isVoice = req.body.voiceNote === 'true';
  const dataUrl = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;

  let msg;
  let found = false;
  await writeDb((d) => {
    const conv = (d.chatConversations || []).find((c) => c.id === conversationId);
    if (!conv) return d;
    found = true;

    let safeReplyTo = null;
    if (replyToMessageId) {
      const orig = (d.chatMessages || []).find((m) => m.id === replyToMessageId && m.conversationId === conversationId);
      if (orig) safeReplyTo = replyToMessageId;
    }

    msg = {
      id: crypto.randomUUID(),
      conversationId,
      senderId: null,
      senderRole: 'admin',
      messageType: isVoice ? 'voice' : 'attachment',
      text,
      replyToMessageId: safeReplyTo,
      createdAt: new Date().toISOString(),
    };
    if (isVoice) {
      msg.voiceNote = { dataUrl, filename: req.file.originalname, size: req.file.size, mimetype: req.file.mimetype };
    } else {
      msg.attachment = { dataUrl, filename: req.file.originalname, size: req.file.size, mimetype: req.file.mimetype };
    }
    (d.chatMessages = d.chatMessages || []).push(msg);
    conv.memberUnreadCount = (conv.memberUnreadCount || 0) + 1;
    return d;
  });

  if (!found) return res.status(404).json({ error: 'Conversation not found' });
  res.json({ ok: true, message: msg });
});

// POST /api/admin/chat/resolve/:conversationId — toggle resolve/reopen
app.post('/api/admin/chat/resolve/:conversationId', requireAdmin, async (req, res) => {
  const convId = req.params.conversationId;
  let updated;
  await writeDb((d) => {
    const conv = (d.chatConversations || []).find((c) => c.id === convId);
    if (!conv) return d;
    conv.resolved = !conv.resolved;
    conv.resolvedAt = conv.resolved ? new Date().toISOString() : null;
    conv.resolvedBy = conv.resolved ? 'admin' : null;
    updated = conv;
    return d;
  });
  if (!updated) return res.status(404).json({ error: 'Conversation not found' });
  res.json({ ok: true, resolved: updated.resolved });
});

// GET /api/admin/chat/unread-count — total unread across all conversations
app.get('/api/admin/chat/unread-count', requireAdmin, (req, res) => {
  const db = readDb();
  const total = (db.chatConversations || []).reduce((sum, c) => sum + (c.adminUnreadCount || 0), 0);
  res.json({ totalUnread: total });
});

/* ---------- Admin push notifications (phone alerts for new chat messages) ---------- */

// GET /api/admin/push/public-key — VAPID public key the browser needs to subscribe
app.get('/api/admin/push/public-key', requireAdmin, (req, res) => {
  if (!PUSH_ENABLED) return res.status(503).json({ error: 'Push notifications are not configured on this server.' });
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

// POST /api/admin/push/subscribe — save a browser's push subscription (one per device)
app.post('/api/admin/push/subscribe', requireAdmin, async (req, res) => {
  const subscription = req.body?.subscription;
  if (!subscription?.endpoint || !subscription?.keys) {
    return res.status(400).json({ error: 'Invalid push subscription' });
  }
  await writeDb((d) => {
    d.pushSubscriptions = (d.pushSubscriptions || []).filter((s) => s.endpoint !== subscription.endpoint);
    d.pushSubscriptions.push({ endpoint: subscription.endpoint, subscription, createdAt: new Date().toISOString() });
    return d;
  });
  res.json({ ok: true });
});

// POST /api/admin/push/unsubscribe — remove this device's subscription
app.post('/api/admin/push/unsubscribe', requireAdmin, async (req, res) => {
  const endpoint = req.body?.endpoint;
  await writeDb((d) => {
    d.pushSubscriptions = (d.pushSubscriptions || []).filter((s) => s.endpoint !== endpoint);
    return d;
  });
  res.json({ ok: true });
});

/* ---------- Broadcast endpoints ---------- */

// POST /api/admin/chat/broadcast — admin sends a broadcast message
app.post('/api/admin/chat/broadcast', requireAdmin, async (req, res) => {
  const { text } = req.body || {};
  if (!text || !String(text).trim()) {
    return res.status(400).json({ error: 'Broadcast text is required' });
  }
  if (String(text).length > 2000) {
    return res.status(400).json({ error: 'Message too long (max 2000 characters)' });
  }
  const msg = {
    id: crypto.randomUUID(),
    text: String(text).trim(),
    createdAt: new Date().toISOString(),
  };
  await writeDb((d) => { (d.broadcasts = d.broadcasts || []).push(msg); return d; });
  res.json({ ok: true, message: msg });
});

// GET /api/admin/chat/broadcasts — list all broadcasts (admin)
app.get('/api/admin/chat/broadcasts', requireAdmin, (req, res) => {
  const db = readDb();
  res.json({ broadcasts: (db.broadcasts || []).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)) });
});

// GET /api/chat/broadcasts — member gets broadcasts (predictions page, logged-in only)
app.get('/api/chat/broadcasts', requireMember, (req, res) => {
  const db = readDb();
  res.json({ broadcasts: (db.broadcasts || []).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)) });
});

// DELETE /api/admin/chat/broadcast/:id — admin permanently deletes a broadcast
app.delete('/api/admin/chat/broadcast/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  let existed = false;
  await writeDb((d) => {
    const before = (d.broadcasts || []).length;
    d.broadcasts = (d.broadcasts || []).filter((b) => b.id !== id);
    existed = (d.broadcasts || []).length < before;
    return d;
  });
  if (!existed) return res.status(404).json({ error: 'Broadcast not found' });
  res.json({ ok: true });
});

// DELETE /api/admin/chat/message/:id — admin deletes a chat message
app.delete('/api/admin/chat/message/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  await writeDb((d) => {
    d.chatMessages = (d.chatMessages || []).filter((m) => m.id !== id);
    d.broadcasts = (d.broadcasts || []).filter((m) => m.id !== id);
    return d;
  });
  res.json({ ok: true });
});

// POST /api/admin/chat/cleanup — remove messages with broken file URLs (pre-base64)
app.post('/api/admin/chat/cleanup', requireAdmin, async (req, res) => {
  let removed = 0;
  await writeDb((d) => {
    const before = (d.chatMessages || []).length;
    d.chatMessages = (d.chatMessages || []).filter((m) => {
      if (m.attachment && m.attachment.url && !m.attachment.dataUrl) return false;
      if (m.voiceNote && m.voiceNote.url && !m.voiceNote.dataUrl) return false;
      return true;
    });
    removed = before - d.chatMessages.length;
    return d;
  });
  res.json({ ok: true, removed });
});

// ---------------------------- Static hosting ----------------------------
const PUBLIC_DIR = path.join(__dirname, 'public');

// Admin dashboard HTML pages are gated server-side: login.html is always
// public, everything else under /admin/ requires a valid session cookie.
// Also handles extensionless URLs (e.g. /admin/dashboard → dashboard.html).
app.get('/admin/:page', (req, res, next) => {
  const page = req.params.page;
  if (page === 'login.html' || page === 'login') return next();

  const token = req.cookies.pbi_admin_session;
  if (!token) return res.redirect('/admin/login.html');
  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    res.clearCookie('pbi_admin_session');
    return res.redirect('/admin/login.html');
  }

  // If the URL has no .html extension, try to serve the .html file directly
  const filePath = path.join(PUBLIC_DIR, 'admin', page);
  if (!path.extname(page)) {
    const htmlPath = filePath + '.html';
    if (fs.existsSync(htmlPath)) {
      return res.sendFile(htmlPath);
    }
  }
  next();
});

app.use(express.static(PUBLIC_DIR));

app.get('/admin', (req, res) => res.redirect('/admin/dashboard.html'));

app.use((req, res) => res.status(404).sendFile(path.join(PUBLIC_DIR, '404.html'), (err) => {
  if (err) res.status(404).send('Not found');
}));

async function start() {
  // Initialize the database (PostgreSQL in production, JSON file locally).
  // Must happen before any route that calls readDb()/writeDb().
  await initDb();

  app.listen(PORT, () => {
    console.log(`Penya Blaugrana Islamabad server running on http://localhost:${PORT}`);
    // Start the fixture sync scheduler (fires an immediate sync at boot).
    startFixtureSync();
  });
}

start().catch((err) => {
  console.error('[fatal] Failed to start server:', err);
  process.exit(1);
});
