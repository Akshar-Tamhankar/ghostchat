const express = require('express');
const http = require('http');
const crypto = require('crypto');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: false }, maxHttpBufferSize: 8_000_000 });

/* ---------------- AUTH (challenge-response) ---------------- */
const ROOM_PASSWORD = process.env.ROOM_PASSWORD || 'oviyaandakshar';
const PBKDF2_ITERATIONS = 210000;
const AUTH_SALT = 'ghostchat::auth::v2';
const EXPECTED_AUTH_KEY = crypto.pbkdf2Sync(ROOM_PASSWORD, AUTH_SALT, PBKDF2_ITERATIONS, 32, 'sha256');

if (ROOM_PASSWORD === 'oviyaandakshar') {
  console.warn('[security] Using the default password. Set ROOM_PASSWORD env var in production.');
}

function expectedResponse(challenge) {
  return crypto.createHmac('sha256', EXPECTED_AUTH_KEY).update(challenge).digest();
}
function verify(challenge, responseHex) {
  if (typeof responseHex !== 'string' || !/^[0-9a-f]{64}$/i.test(responseHex)) return false;
  const given = Buffer.from(responseHex, 'hex');
  const want = expectedResponse(challenge);
  if (given.length !== want.length) return false;
  return crypto.timingSafeEqual(given, want);
}

/* ---------------- BRUTE-FORCE PROTECTION ---------------- */
const FREE_TRIES = 5;
const MAX_LOCK_MS = 5 * 60 * 1000;
const attempts = new Map();
const lockState = ip => attempts.get(ip) || { fails: 0, lockedUntil: 0 };
const lockedMsLeft = ip => Math.max(0, lockState(ip).lockedUntil - Date.now());
function recordFail(ip) {
  const s = lockState(ip);
  s.fails += 1;
  if (s.fails > FREE_TRIES) s.lockedUntil = Date.now() + Math.min(MAX_LOCK_MS, 1000 * Math.pow(2, s.fails - FREE_TRIES));
  attempts.set(ip, s);
}
const recordSuccess = ip => attempts.delete(ip);

/* ---------------- SECURITY HEADERS ---------------- */
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "connect-src 'self' ws: wss:",
    "img-src 'self' data:",
    "media-src 'self' blob:",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'"
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

/* ---------------- VALIDATION ---------------- */
// Explicit code points so server and client compare byte-identical strings.
const EMOJI = ['\u2764\uFE0F', '\u{1F940}', '\u{1F480}']; // ❤️ 🥀 💀
const ALLOWED_EMOJI = new Set(EMOJI);
const MAX_NAME = 20;
const MAX_CIPHERTEXT = 8000;
const MAX_IMAGE_CIPHERTEXT = 7_000_000;   // base64 of an encrypted image (~5 MB binary); client keeps originals at full quality under this
const ALLOWED_IMAGE_MIME = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
const MAX_SDP = 200000;       // SDP blobs are a few KB; cap generously
const newId = () => crypto.randomBytes(9).toString('base64url');
const clientIp = s => s.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || s.handshake.address || 'unknown';

function roster() {
  return [...(io.sockets.adapter.rooms.get('main') || [])]
    .map(id => io.sockets.sockets.get(id))
    .filter(s => s?.authed)
    .map(s => ({ id: s.id, name: s.username }));
}

/* ---------------- CONNECTION ---------------- */
io.on('connection', (socket) => {
  socket.authed = false;
  socket.challenge = crypto.randomBytes(16).toString('hex');
  socket.emit('challenge', socket.challenge);

  socket.on('join', ({ username, response } = {}) => {
    if (socket.authed) return;
    const ip = clientIp(socket);
    const wait = lockedMsLeft(ip);
    if (wait > 0) { socket.emit('auth_error', { reason: 'locked', retryInMs: wait }); return; }

    if (!verify(socket.challenge, response)) {
      recordFail(ip);
      socket.challenge = crypto.randomBytes(16).toString('hex');
      socket.emit('challenge', socket.challenge);
      socket.emit('auth_error', { reason: 'bad', retryInMs: lockedMsLeft(ip) });
      return;
    }

    recordSuccess(ip);
    socket.username = String(username || '').trim().slice(0, MAX_NAME) || 'anon';
    socket.authed = true;
    socket.join('main');
    socket.emit('joined', { selfId: socket.id, name: socket.username });
    socket.to('main').emit('system', `${socket.username} joined`);
    io.to('main').emit('users', roster());
  });

  socket.on('message', ({ payload, replyToId } = {}) => {
    if (!socket.authed || !payload) return;
    if (typeof payload.iv !== 'string' || typeof payload.ct !== 'string') return;
    if (payload.ct.length > MAX_CIPHERTEXT) return;
    io.to('main').emit('message', {
      id: newId(), senderId: socket.id, senderName: socket.username, payload,
      replyToId: typeof replyToId === 'string' ? replyToId.slice(0, 32) : null,
      time: new Date().toISOString()
    });
  });

  socket.on('image', ({ payload, replyToId } = {}) => {
    if (!socket.authed || !payload) return;
    if (typeof payload.iv !== 'string' || typeof payload.ct !== 'string') return;
    if (typeof payload.mime !== 'string' || !ALLOWED_IMAGE_MIME.has(payload.mime)) return;
    if (payload.iv.length > 64 || payload.ct.length > MAX_IMAGE_CIPHERTEXT) return;
    const w = Math.min(20000, Math.max(0, Number(payload.w) || 0));
    const h = Math.min(20000, Math.max(0, Number(payload.h) || 0));
    io.to('main').emit('image', {
      id: newId(), senderId: socket.id, senderName: socket.username,
      payload: { iv: payload.iv, ct: payload.ct, mime: payload.mime, w, h },
      replyToId: typeof replyToId === 'string' ? replyToId.slice(0, 32) : null,
      time: new Date().toISOString()
    });
  });

  socket.on('typing', (isTyping) => {
    if (!socket.authed) return;
    socket.to('main').emit('typing', { senderId: socket.id, name: socket.username, isTyping: !!isTyping });
  });

  socket.on('react', ({ msgId, emoji, active } = {}) => {
    if (!socket.authed || typeof msgId !== 'string' || !ALLOWED_EMOJI.has(emoji)) return;
    io.to('main').emit('react', { msgId: msgId.slice(0, 32), emoji, active: !!active, senderId: socket.id });
  });

  socket.on('seen', ({ msgId } = {}) => {
    if (!socket.authed || typeof msgId !== 'string') return;
    socket.to('main').emit('seen', { msgId: msgId.slice(0, 32), senderId: socket.id });
  });

  socket.on('delete', ({ msgId } = {}) => {
    if (!socket.authed || typeof msgId !== 'string') return;
    socket.to('main').emit('delete', { msgId: msgId.slice(0, 32), senderId: socket.id });
  });

  /* -------- WebRTC signaling (server only relays; media is P2P) -------- */
  socket.on('call-offer', ({ sdp, kind } = {}) => {
    if (!socket.authed || typeof sdp !== 'string' || sdp.length > MAX_SDP) return;
    if (kind !== 'audio' && kind !== 'video') return;
    socket.to('main').emit('call-offer', { sdp, kind, from: socket.id, name: socket.username });
  });
  socket.on('call-answer', ({ sdp } = {}) => {
    if (!socket.authed || typeof sdp !== 'string' || sdp.length > MAX_SDP) return;
    socket.to('main').emit('call-answer', { sdp, from: socket.id });
  });
  socket.on('ice-candidate', ({ candidate } = {}) => {
    if (!socket.authed || !candidate) return;
    socket.to('main').emit('ice-candidate', { candidate, from: socket.id });
  });
  socket.on('call-decline', () => { if (socket.authed) socket.to('main').emit('call-decline', { from: socket.id }); });
  socket.on('call-busy', () => { if (socket.authed) socket.to('main').emit('call-busy', { from: socket.id }); });
  socket.on('call-end', () => { if (socket.authed) socket.to('main').emit('call-end', { from: socket.id }); });
  // ICE restart / renegotiation to recover a dropped media path mid-call
  socket.on('call-renegotiate', ({ sdp } = {}) => {
    if (!socket.authed || typeof sdp !== 'string' || sdp.length > MAX_SDP) return;
    socket.to('main').emit('call-renegotiate', { sdp, from: socket.id });
  });
  socket.on('call-renegotiate-answer', ({ sdp } = {}) => {
    if (!socket.authed || typeof sdp !== 'string' || sdp.length > MAX_SDP) return;
    socket.to('main').emit('call-renegotiate-answer', { sdp, from: socket.id });
  });
  socket.on('screen-share', ({ on } = {}) => {
    if (socket.authed) socket.to('main').emit('screen-share', { on: !!on });
  });

  socket.on('disconnect', () => {
    if (!socket.authed) return;
    socket.to('main').emit('typing', { senderId: socket.id, isTyping: false });
    // NOTE: deliberately NOT emitting call-end here. A socket disconnect is
    // usually a transient reconnect (Render proxy cycling / network blip) and
    // the P2P media connection is independent of this socket. Killing the call
    // on every signaling blip is what made calls "drop after a while". The peer
    // detects a genuinely-dead call via its own WebRTC connectionState instead.
    socket.to('main').emit('system', `${socket.username} left`);
    io.to('main').emit('users', roster());
  });
});

setInterval(() => {
  const now = Date.now();
  for (const [ip, s] of attempts) if (s.lockedUntil < now && s.fails <= FREE_TRIES) attempts.delete(ip);
}, 60000).unref();

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`ghostchat running on port ${PORT}`));
