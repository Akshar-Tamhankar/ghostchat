'use strict';
/* ghostchat — single-file client. No ES modules so there's nothing to misdeploy.
   Sections: constants · crypto · CallManager · ChatUI · init. */
(function () {

const $ = id => document.getElementById(id);
const EMOJI = ['\u2764\uFE0F', '\u{1F940}', '\u{1F480}']; // ❤️ 🥀 💀 — must match server

/* ============================ CRYPTO ============================ */
const ITERATIONS = 210000;
const AUTH_SALT = 'ghostchat::auth::v2';
const MSG_SALT = 'ghostchat::msg::v2';
const _enc = new TextEncoder();
const _dec = new TextDecoder();
const toHex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
function toB64(bytes) { let s = ''; const a = new Uint8Array(bytes); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
function fromB64(b64) { const s = atob(b64); const a = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; }

function deriveBaseKey(password) {
  return crypto.subtle.importKey('raw', _enc.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
}
function deriveMsgKey(baseKey) {
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: _enc.encode(MSG_SALT), iterations: ITERATIONS, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function authResponse(baseKey, challenge) {
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: _enc.encode(AUTH_SALT), iterations: ITERATIONS, hash: 'SHA-256' }, baseKey, 256);
  const k = await crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', k, _enc.encode(challenge)));
}
async function encryptText(msgKey, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, msgKey, _enc.encode(text));
  return { iv: toB64(iv), ct: toB64(ct) };
}
async function decryptText(msgKey, p) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(p.iv) }, msgKey, fromB64(p.ct));
  return _dec.decode(pt);
}
// Images ride the same AES-GCM channel as text — the server only ever relays ciphertext.
async function encryptBytes(msgKey, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, msgKey, bytes);
  return { iv: toB64(iv), ct: toB64(ct) };
}
async function decryptBytes(msgKey, p) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(p.iv) }, msgKey, fromB64(p.ct));
  return new Uint8Array(pt);
}

/* ============================ IMAGES ============================ */
// High quality by design: originals are sent byte-for-byte whenever they fit the transmit cap
// (full resolution, no re-encode). Only images larger than the cap are downscaled — and even
// then at a generous edge/quality — so ordinary photos never lose detail.
const IMG_MAX_DIM = 2560;                 // longest edge, only applied to oversized images
const IMG_SEND_MAX = 5_000_000;           // hard cap on the bytes we actually transmit (~5 MB)
const PASS_THROUGH_MAX = 5_000_000;       // originals up to this are sent untouched, full quality
const ALLOWED_IMG_MIME = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);

const canvasToBlob = (canvas, type, q) => new Promise(res => canvas.toBlob(res, type, q));
// Prefer WebP (smaller at equal quality) and fall back to JPEG where the browser can't encode it.
async function encodeCanvas(canvas, quality) {
  const webp = await canvasToBlob(canvas, 'image/webp', quality);
  if (webp && webp.type === 'image/webp') return webp;
  return canvasToBlob(canvas, 'image/jpeg', quality);
}

// Decode via createImageBitmap (works off a Blob directly — no blob: URL, so the strict
// img-src CSP is never involved). Originals within the cap pass through untouched (keeps PNG
// transparency / GIF animation / full quality); only oversized images are downscaled and
// re-encoded, high quality first, easing off only as much as needed to fit the cap.
async function prepareImage(file) {
  if (!file.type.startsWith('image/')) throw new Error('not an image');
  const bmp = await createImageBitmap(file);
  const w0 = bmp.width, h0 = bmp.height;
  try {
    if (file.size <= PASS_THROUGH_MAX && ALLOWED_IMG_MIME.has(file.type)) {
      return { bytes: new Uint8Array(await file.arrayBuffer()), mime: file.type, w: w0, h: h0 };
    }
    let scale = Math.min(1, IMG_MAX_DIM / Math.max(w0, h0)), quality = 0.92;
    for (let pass = 0; pass < 7; pass++) {
      const w = Math.max(1, Math.round(w0 * scale)), h = Math.max(1, Math.round(h0 * scale));
      const canvas = document.createElement('canvas'); canvas.width = w; canvas.height = h;
      const ctx = canvas.getContext('2d');
      ctx.imageSmoothingEnabled = true; ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(bmp, 0, 0, w, h);
      const blob = await encodeCanvas(canvas, quality);
      if (blob && (blob.size <= IMG_SEND_MAX || pass === 6)) {
        return { bytes: new Uint8Array(await blob.arrayBuffer()), mime: blob.type || 'image/jpeg', w, h };
      }
      if (quality > 0.7) quality -= 0.08; else scale *= 0.85;
    }
    throw new Error('could not compress');
  } finally { if (bmp.close) bmp.close(); }
}

/* ============================ CALLS ============================ */
const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun1.l.google.com:19302' }];
const VIDEO_CONSTRAINTS = { width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30, max: 30 }, facingMode: 'user' };
const AUDIO_CONSTRAINTS = { echoCancellation: true, noiseSuppression: true, autoGainControl: true };
const MAX_VIDEO_BITRATE = 6_000_000;   // ~6 Mbps, near-pristine 1080p30 (you have 30 Mbps up, so plenty of room)
const RECOVER_MS = 15000;

function mediaErrorMsg(e, kind) {
  const dev = kind === 'video' ? 'camera/microphone' : 'microphone';
  if (e.name === 'NotAllowedError' || e.name === 'SecurityError') return `${dev} permission denied. Tap the camera/mic icon in the address bar, allow access, then retry.`;
  if (e.name === 'NotFoundError' || e.name === 'OverconstrainedError') return `No ${dev} found on this device.`;
  if (e.name === 'NotReadableError') return `Your ${dev} is already in use by another tab or app (common when testing two tabs on one computer). Close it and retry.`;
  return `Could not access ${dev}: ${e.message || e.name}. Calls need the live HTTPS site (or localhost).`;
}

class CallManager {
  constructor(socket) {
    this.socket = socket;
    this.pc = null; this.localStream = null; this.cameraTrack = null; this.screenStream = null;
    this.state = 'idle'; this.kind = 'video'; this.isCaller = false; this.sharing = false;
    this.pendingOffer = null; this.pendingCandidates = []; this.recoverTimer = null; this._suppressExpand = false;
    this._bindSocket(); this._wireControls();
  }
  start(kind) { if (this.state === 'idle') this._startCall(kind); }

  _bindSocket() {
    const s = this.socket;
    s.on('call-offer', d => this._onOffer(d));
    s.on('call-answer', d => this._onAnswer(d));
    s.on('ice-candidate', d => this._onIce(d));
    s.on('call-renegotiate', d => this._onReneg(d));
    s.on('call-renegotiate-answer', d => this._onRenegAnswer(d));
    s.on('call-decline', () => { if (this.state === 'calling') { this._status('call declined'); setTimeout(() => this.end(), 1200); } });
    s.on('call-busy', () => { if (this.state === 'calling') { this._status('busy'); setTimeout(() => this.end(), 1200); } });
    s.on('call-end', () => { if (this.state !== 'idle') this.end(true); });
    s.on('screen-share', ({ on }) => $('call-overlay').classList.toggle('remote-screen', !!on));
  }
  _wireControls() {
    $('mute-btn').addEventListener('click', () => this.toggleMute());
    $('cam-btn').addEventListener('click', () => this.toggleCamera());
    $('screen-btn').addEventListener('click', () => this.toggleScreen());
    $('hangup-btn').addEventListener('click', () => this.end());
    $('ic-accept').addEventListener('click', () => this.accept());
    $('ic-decline').addEventListener('click', () => this.decline());
    $('min-btn').addEventListener('click', e => { e.stopPropagation(); this.minimize(); });
    $('mini-hangup').addEventListener('click', e => { e.stopPropagation(); this.end(); });
    $('call-overlay').addEventListener('click', () => {
      if (this._suppressExpand) return;
      if ($('call-overlay').classList.contains('minimized')) this.expand();
    });
    this._initDrag();
    // screen capture isn't available on iOS / some mobile browsers — hide the button there
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) $('screen-btn').style.display = 'none';
  }
  minimize() { this._resetMiniPos(); $('call-overlay').classList.add('minimized'); }
  expand() { $('call-overlay').classList.remove('minimized'); this._resetMiniPos(); }
  _resetMiniPos() { const o = $('call-overlay'); o.style.left = o.style.top = o.style.right = o.style.bottom = ''; }
  _initDrag() {
    const ov = $('call-overlay'); const app = document.getElementById('app');
    let dragging = false, ox = 0, oy = 0, sx = 0, sy = 0;
    ov.addEventListener('pointerdown', e => {
      if (!ov.classList.contains('minimized') || e.target.id === 'mini-hangup') return;
      dragging = true; this._suppressExpand = false;
      const r = ov.getBoundingClientRect();
      ox = e.clientX - r.left; oy = e.clientY - r.top; sx = e.clientX; sy = e.clientY;
      try { ov.setPointerCapture(e.pointerId); } catch (err) {}
    });
    ov.addEventListener('pointermove', e => {
      if (!dragging) return;
      const ar = app.getBoundingClientRect();
      let left = Math.max(0, Math.min(e.clientX - ar.left - ox, ar.width - ov.offsetWidth));
      let top = Math.max(0, Math.min(e.clientY - ar.top - oy, ar.height - ov.offsetHeight));
      ov.style.left = left + 'px'; ov.style.top = top + 'px'; ov.style.right = 'auto'; ov.style.bottom = 'auto';
      if (Math.abs(e.clientX - sx) > 5 || Math.abs(e.clientY - sy) > 5) this._suppressExpand = true; // it's a drag, not a tap
    });
    const endDrag = e => { if (!dragging) return; dragging = false; try { ov.releasePointerCapture(e.pointerId); } catch (err) {} };
    ov.addEventListener('pointerup', endDrag);
    ov.addEventListener('pointercancel', endDrag);
  }
  _buildPC() {
    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    pc.onicecandidate = e => { if (e.candidate) this.socket.emit('ice-candidate', { candidate: e.candidate }); };
    pc.ontrack = e => { const v = $('remote-video'); v.srcObject = e.streams[0]; const p = v.play(); if (p && p.catch) p.catch(() => {}); };
    pc.onconnectionstatechange = () => {
      if (!this.pc) return;
      const st = this.pc.connectionState;
      if (st === 'connected') { this._status('connected'); this._clearRecover(); }
      else if (st === 'disconnected') { this._status('connection unstable…'); this._scheduleRecover(); }
      else if (st === 'failed') { this._status('reconnecting…'); this._tryIceRestart(); this._scheduleRecover(); }
    };
    this.pc = pc;
  }
  async _getMedia(kind) {
    this.localStream = await navigator.mediaDevices.getUserMedia({ audio: AUDIO_CONSTRAINTS, video: kind === 'video' ? VIDEO_CONSTRAINTS : false });
    const lv = $('local-video'); lv.srcObject = this.localStream; const lp = lv.play(); if (lp && lp.catch) lp.catch(() => {});
    this.cameraTrack = this.localStream.getVideoTracks()[0] || null;
    this.localStream.getTracks().forEach(t => this.pc.addTrack(t, this.localStream));
    this._applyMutedDefault();
  }
  _applyMutedDefault() {
    const a = this.localStream.getAudioTracks()[0], v = this.localStream.getVideoTracks()[0];
    if (a) a.enabled = false;
    if (v) v.enabled = false;
    this._setBtn('mute-btn', false, '🎙️', '🔇');
    this._setBtn('cam-btn', false, '📷', '🚫');
  }
  async _applyTuning() {
    const sender = this.pc.getSenders().find(s => s.track && s.track.kind === 'video');
    if (!sender) return;
    try {
      const p = sender.getParameters();
      if (!p.encodings || !p.encodings.length) p.encodings = [{}];
      p.encodings[0].maxBitrate = MAX_VIDEO_BITRATE; p.encodings[0].maxFramerate = 30;
      try { p.degradationPreference = 'balanced'; } catch (e) {}
      await sender.setParameters(p);
    } catch (e) { console.warn('bitrate tuning skipped:', e.message); }
  }
  async _flushCandidates() { for (const c of this.pendingCandidates) { try { await this.pc.addIceCandidate(c); } catch (e) {} } this.pendingCandidates = []; }

  async _startCall(kind) {
    this.kind = kind; this.state = 'calling'; this.isCaller = true; this._buildPC();
    try { await this._getMedia(kind); }
    catch (e) { console.error('getUserMedia:', e.name, e.message); this.end(); alert(mediaErrorMsg(e, kind)); return; }
    this._showUI(kind); this._status(kind === 'video' ? 'video calling…' : 'calling…'); $('call-peer').textContent = '';
    try {
      const offer = await this.pc.createOffer(); await this.pc.setLocalDescription(offer); await this._applyTuning();
      this.socket.emit('call-offer', { sdp: JSON.stringify(offer), kind });
    } catch (e) { console.error('offer:', e); this.end(); alert('Failed to start the call.'); }
  }
  _onOffer({ sdp, kind, name }) {
    if (this.state !== 'idle') { this.socket.emit('call-busy'); return; }
    this.state = 'incoming'; this.pendingOffer = { sdp, kind, name };
    $('ic-kind').textContent = kind === 'video' ? 'incoming video call' : 'incoming voice call';
    $('ic-name').textContent = name || 'someone';
    $('incoming-call').classList.add('show');
  }
  async accept() {
    if (!this.pendingOffer) return;
    const { sdp, kind, name } = this.pendingOffer;
    this.kind = kind; this.isCaller = false; $('incoming-call').classList.remove('show'); this._buildPC();
    try { await this._getMedia(kind); }
    catch (e) { console.error('getUserMedia:', e.name, e.message); this.end(); this.socket.emit('call-end'); alert(mediaErrorMsg(e, kind)); return; }
    this._showUI(kind); $('call-peer').textContent = name || ''; this._status('connecting…');
    await this.pc.setRemoteDescription(JSON.parse(sdp)); await this._flushCandidates();
    const answer = await this.pc.createAnswer(); await this.pc.setLocalDescription(answer); await this._applyTuning();
    this.socket.emit('call-answer', { sdp: JSON.stringify(answer) });
    this.state = 'connected'; this.pendingOffer = null;
  }
  decline() { this.socket.emit('call-decline'); this.pendingOffer = null; this.state = 'idle'; this._hideUI(); }
  async _onAnswer({ sdp }) {
    if (!this.pc || this.state !== 'calling') return;
    await this.pc.setRemoteDescription(JSON.parse(sdp)); await this._flushCandidates();
    this.state = 'connected'; this._status('connected');
  }
  async _onIce({ candidate }) {
    if (!this.pc) return;
    if (this.pc.remoteDescription && this.pc.remoteDescription.type) { try { await this.pc.addIceCandidate(candidate); } catch (e) {} }
    else this.pendingCandidates.push(candidate);
  }
  async _tryIceRestart() {
    if (!this.isCaller || !this.pc) return;
    try { const o = await this.pc.createOffer({ iceRestart: true }); await this.pc.setLocalDescription(o); this.socket.emit('call-renegotiate', { sdp: JSON.stringify(o) }); }
    catch (e) { console.error('ICE restart:', e); }
  }
  async _onReneg({ sdp }) {
    if (!this.pc || this.state !== 'connected') return;
    try {
      await this.pc.setRemoteDescription(JSON.parse(sdp)); await this._flushCandidates();
      const a = await this.pc.createAnswer(); await this.pc.setLocalDescription(a);
      this.socket.emit('call-renegotiate-answer', { sdp: JSON.stringify(a) });
    } catch (e) { console.error('reneg callee:', e); }
  }
  async _onRenegAnswer({ sdp }) { if (this.pc) { try { await this.pc.setRemoteDescription(JSON.parse(sdp)); } catch (e) { console.error('reneg answer:', e); } } }
  _scheduleRecover() {
    if (this.recoverTimer) return;
    this.recoverTimer = setTimeout(() => { this.recoverTimer = null; if (this.pc && this.pc.connectionState !== 'connected') { this._status('call lost'); setTimeout(() => this.end(), 800); } }, RECOVER_MS);
  }
  _clearRecover() { if (this.recoverTimer) { clearTimeout(this.recoverTimer); this.recoverTimer = null; } }

  toggleMute() { const t = this.localStream && this.localStream.getAudioTracks()[0]; if (!t) return; t.enabled = !t.enabled; this._setBtn('mute-btn', t.enabled, '🎙️', '🔇'); }
  toggleCamera() { const t = this.cameraTrack; if (!t || this.sharing) return; t.enabled = !t.enabled; this._setBtn('cam-btn', t.enabled, '📷', '🚫'); }
  async toggleScreen() {
    if (this.kind !== 'video' || this.state !== 'connected') return;
    const sender = this.pc.getSenders().find(s => s.track && s.track.kind === 'video');
    if (!sender) return;
    if (!this.sharing) {
      let stream; try { stream = await navigator.mediaDevices.getDisplayMedia({ video: true }); } catch (e) { return; }
      this.screenStream = stream; const screenTrack = stream.getVideoTracks()[0];
      await sender.replaceTrack(screenTrack); $('local-video').srcObject = stream;
      $('local-video').classList.add('screen');
      this.sharing = true; $('screen-btn').classList.add('active');
      this.socket.emit('screen-share', { on: true });
      screenTrack.onended = () => this._stopScreen(sender);
    } else this._stopScreen(sender);
  }
  async _stopScreen(sender) {
    if (this.screenStream) { this.screenStream.getTracks().forEach(t => t.stop()); this.screenStream = null; }
    if (this.cameraTrack) await sender.replaceTrack(this.cameraTrack);
    $('local-video').srcObject = this.localStream; $('local-video').classList.remove('screen');
    this.sharing = false; $('screen-btn').classList.remove('active');
    this.socket.emit('screen-share', { on: false });
  }
  end(remote) {
    if (!remote && this.state !== 'idle') this.socket.emit('call-end');
    this._clearRecover();
    if (this.screenStream) { this.screenStream.getTracks().forEach(t => t.stop()); this.screenStream = null; }
    if (this.localStream) { this.localStream.getTracks().forEach(t => t.stop()); this.localStream = null; }
    if (this.pc) { this.pc.onicecandidate = this.pc.ontrack = this.pc.onconnectionstatechange = null; this.pc.close(); this.pc = null; }
    $('remote-video').srcObject = null; $('local-video').srcObject = null;
    this.cameraTrack = null; this.pendingCandidates = []; this.pendingOffer = null;
    this.state = 'idle'; this.isCaller = false; this.sharing = false;
    this._resetButtons(); this._hideUI();
  }
  _status(t) { $('call-status').textContent = t; }
  _showUI(kind) { const o = $('call-overlay'); o.classList.add('show'); o.classList.toggle('audio', kind === 'audio'); }
  _hideUI() {
    const o = $('call-overlay');
    o.classList.remove('show', 'minimized', 'remote-screen');
    o.style.left = o.style.top = o.style.right = o.style.bottom = '';
    $('local-video').classList.remove('screen');
    $('incoming-call').classList.remove('show');
  }
  _setBtn(id, on, onIcon, offIcon) { const b = $(id); b.classList.toggle('off', !on); b.textContent = on ? onIcon : offIcon; }
  _resetButtons() { this._setBtn('mute-btn', true, '🎙️', '🔇'); this._setBtn('cam-btn', true, '📷', '🚫'); $('screen-btn').classList.remove('active'); }
}

/* ============================ CHAT ============================ */
const fmtTime = iso => iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
function autoResize(el) { el.style.height = 'auto'; el.style.height = Math.min(el.scrollHeight, 120) + 'px'; }
function mkBtn(cls, text, onClick) {
  const b = document.createElement('button'); b.className = cls; if (text) b.textContent = text;
  b.addEventListener('click', e => { e.stopPropagation(); onClick(); });
  return b;
}

class ChatUI {
  constructor(socket) {
    this.socket = socket; this.selfId = ''; this.msgKey = null; this.replyTarget = null;
    this.msgStore = new Map(); this.reactions = new Map(); this.myReactions = new Map();
    this.unseen = new Set(); this.typingPeople = new Map(); this.typingSent = false; this.typingTimer = null;
    this._bindSocket();
  }
  setSelfId(id) { this.selfId = id; }
  setMsgKey(k) { this.msgKey = k; }
  wire() {
    $('send-btn').addEventListener('click', () => this.send());
    $('rp-close').addEventListener('click', () => this._clearReply());
    const inp = $('msg-input');
    inp.addEventListener('input', () => this._onActivity());
    inp.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.send(); }
      if (e.key === 'Escape' && this.replyTarget) this._clearReply();
    });
    inp.addEventListener('blur', () => this._stopTyping());
    document.addEventListener('visibilitychange', () => this.flushSeen());
    window.addEventListener('focus', () => this.flushSeen());

    // --- picture sending: button, paste, drag-drop ---
    const fileInput = $('file-input');
    $('attach-btn').addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => { const files = [...fileInput.files]; fileInput.value = ''; files.forEach(f => this.sendImage(f)); });
    inp.addEventListener('paste', e => {
      const items = (e.clipboardData && e.clipboardData.items) || [];
      for (const it of items) if (it.type.startsWith('image/')) { const f = it.getAsFile(); if (f) { e.preventDefault(); this.sendImage(f); } }
    });
    const chatEl = $('chat');
    ['dragover', 'dragenter'].forEach(ev => chatEl.addEventListener(ev, e => e.preventDefault()));
    chatEl.addEventListener('drop', e => {
      e.preventDefault();
      const files = (e.dataTransfer && e.dataTransfer.files) || [];
      [...files].forEach(f => { if (f.type.startsWith('image/')) this.sendImage(f); });
    });
    // --- fullscreen image viewer ---
    $('image-viewer').addEventListener('click', () => this._closeViewer());
    document.addEventListener('keydown', e => { if (e.key === 'Escape') this._closeViewer(); });
  }
  _bindSocket() {
    const s = this.socket;
    s.on('message', m => this._onMessage(m));
    s.on('image', m => this._onImage(m));
    s.on('react', d => this._onReact(d));
    s.on('seen', d => this._onSeen(d));
    s.on('typing', d => this._onTyping(d));
    s.on('delete', d => this._applyDelete(d.msgId));
    s.on('system', t => this.addSystem(t));
    s.on('users', u => this._onUsers(u));
  }
  async send() {
    const inp = $('msg-input'); const text = inp.value.trim();
    if (!text || !this.msgKey) return;
    const replyToId = this.replyTarget ? this.replyTarget.id : null;
    try { this.socket.emit('message', { payload: await encryptText(this.msgKey, text), replyToId }); } catch (e) { return; }
    inp.value = ''; inp.style.height = 'auto'; this._clearReply(); this._stopTyping();
  }
  async _onMessage(m) {
    let text = '', undecryptable = false;
    try { text = await decryptText(this.msgKey, m.payload); } catch (e) { undecryptable = true; }
    if (!undecryptable) this.msgStore.set(m.id, { name: m.senderName, text });
    this._render({ ...m, text, undecryptable });
    if (m.senderId !== this.selfId) { this.unseen.add(m.id); this.flushSeen(); }
  }
  async sendImage(file) {
    if (!this.msgKey || !file) return;
    let prep;
    try { prep = await prepareImage(file); }
    catch (e) { this.addSystem('couldn’t process that image'); return; }
    const replyToId = this.replyTarget ? this.replyTarget.id : null;
    try {
      const enc = await encryptBytes(this.msgKey, prep.bytes);
      this.socket.emit('image', { payload: { ...enc, mime: prep.mime, w: prep.w, h: prep.h }, replyToId });
    } catch (e) { this.addSystem('couldn’t send that image'); return; }
    this._clearReply();
  }
  async _onImage(m) {
    let src = '', undecryptable = false;
    const p = m.payload || {};
    const mime = ALLOWED_IMG_MIME.has(p.mime) ? p.mime : 'image/jpeg';
    try { src = `data:${mime};base64,${toB64(await decryptBytes(this.msgKey, p))}`; }
    catch (e) { undecryptable = true; }
    if (!undecryptable) this.msgStore.set(m.id, { name: m.senderName, text: '📷 photo' });
    this._render({ ...m, image: src, imgW: p.w, imgH: p.h, undecryptable });
    if (m.senderId !== this.selfId) { this.unseen.add(m.id); this.flushSeen(); }
  }
  _openViewer(src) { $('viewer-img').src = src; $('image-viewer').classList.add('show'); }
  _closeViewer() { const v = $('image-viewer'); if (v.classList.contains('show')) { v.classList.remove('show'); $('viewer-img').removeAttribute('src'); } }
  _render({ id, senderId, senderName, text, time, replyToId, undecryptable, image, imgW, imgH }) {
    const box = $('messages'); const mine = senderId === this.selfId;
    const w = document.createElement('div'); w.className = 'msg ' + (mine ? 'self' : 'other'); w.dataset.id = id;
    const meta = document.createElement('div'); meta.className = 'msg-meta'; meta.textContent = `${senderName} · ${fmtTime(time)}`; w.appendChild(meta);
    const bubble = document.createElement('div'); bubble.className = 'msg-bubble' + (undecryptable ? ' undecryptable' : '');
    if (replyToId && this.msgStore.has(replyToId)) {
      const q = this.msgStore.get(replyToId); const quote = document.createElement('div'); quote.className = 'quote';
      const qn = document.createElement('span'); qn.className = 'q-name'; qn.textContent = q.name;
      const qt = document.createElement('span'); qt.className = 'q-text'; qt.textContent = q.text;
      quote.appendChild(qn); quote.appendChild(qt); bubble.appendChild(quote);
    }
    if (image && !undecryptable) {
      bubble.classList.add('has-image');
      const el = document.createElement('img'); el.className = 'msg-image'; el.alt = 'shared photo'; el.decoding = 'async';
      if (imgW && imgH) el.style.aspectRatio = imgW + ' / ' + imgH;
      el.addEventListener('load', () => { box.scrollTop = box.scrollHeight; });
      el.addEventListener('click', e => { e.stopPropagation(); this._openViewer(image); });
      el.src = image; bubble.appendChild(el);
    } else {
      const body = document.createElement('span'); body.textContent = undecryptable ? '⚠ unable to decrypt this message' : text; bubble.appendChild(body);
    }
    bubble.addEventListener('click', () => w.classList.toggle('actions-open'));
    w.appendChild(bubble);
    if (mine) { const st = document.createElement('div'); st.className = 'msg-status'; st.textContent = 'sent'; w.appendChild(st); }
    const summary = document.createElement('div'); summary.className = 'msg-reactions'; w.appendChild(summary);
    const actions = document.createElement('div'); actions.className = 'msg-actions';
    actions.appendChild(mkBtn('reply-btn', '↩ reply', () => this._startReply(id)));
    for (const emoji of EMOJI) { const chip = mkBtn('react-chip', emoji, () => this.toggleReaction(id, emoji)); chip.dataset.emoji = emoji; actions.appendChild(chip); }
    if (mine) actions.appendChild(mkBtn('reply-btn', '🚫 unsend', () => this._unsend(id)));
    w.appendChild(actions);
    box.appendChild(w); box.scrollTop = box.scrollHeight; this._refreshReactions(id);
  }
  addSystem(text) {
    const box = $('messages'); const w = document.createElement('div'); w.className = 'msg system';
    const b = document.createElement('div'); b.className = 'msg-bubble'; b.textContent = text; w.appendChild(b);
    box.appendChild(w); box.scrollTop = box.scrollHeight;
  }
  _onActivity() {
    autoResize($('msg-input'));
    if (!this.typingSent) { this.socket.emit('typing', true); this.typingSent = true; }
    clearTimeout(this.typingTimer); this.typingTimer = setTimeout(() => this._stopTyping(), 2500);
  }
  _stopTyping() { clearTimeout(this.typingTimer); if (this.typingSent) { this.socket.emit('typing', false); this.typingSent = false; } }
  _onTyping({ senderId, name, isTyping }) {
    if (senderId === this.selfId) return;
    if (isTyping) this.typingPeople.set(senderId, name || 'someone'); else this.typingPeople.delete(senderId);
    const names = [...this.typingPeople.values()]; const bar = $('typing-bar');
    if (names.length) { $('typing-who').textContent = names.length === 1 ? `${names[0]} is typing` : `${names.join(', ')} are typing`; bar.classList.add('show'); }
    else bar.classList.remove('show');
  }
  _startReply(id) {
    const m = this.msgStore.get(id); if (!m) return;
    this.replyTarget = { id, name: m.name, text: m.text };
    $('rp-name').textContent = 'replying to ' + m.name; $('rp-text').textContent = m.text;
    $('reply-preview').classList.add('show'); $('msg-input').focus();
  }
  _clearReply() { this.replyTarget = null; $('reply-preview').classList.remove('show'); }
  toggleReaction(id, emoji) {
    const mine = this.myReactions.get(id) || new Set(); const active = !mine.has(emoji);
    if (active) mine.add(emoji); else mine.delete(emoji); this.myReactions.set(id, mine);
    this._applyReaction(id, emoji, this.selfId, active); this.socket.emit('react', { msgId: id, emoji, active });
  }
  _onReact({ msgId, emoji, active, senderId }) { if (senderId !== this.selfId) this._applyReaction(msgId, emoji, senderId, active); }
  _applyReaction(id, emoji, senderId, active) {
    let m = this.reactions.get(id); if (!m) { m = {}; this.reactions.set(id, m); }
    if (!m[emoji]) m[emoji] = new Set();
    if (active) m[emoji].add(senderId); else m[emoji].delete(senderId);
    this._refreshReactions(id);
  }
  _refreshReactions(id) {
    const el = document.querySelector(`.msg[data-id="${CSS.escape(id)}"]`); if (!el) return;
    const m = this.reactions.get(id) || {}; const mine = this.myReactions.get(id) || new Set();
    el.querySelectorAll('.react-chip').forEach(c => c.classList.toggle('active', mine.has(c.dataset.emoji)));
    const summary = el.querySelector('.msg-reactions'); summary.textContent = '';
    for (const emoji of EMOJI) {
      const count = m[emoji] ? m[emoji].size : 0; if (!count) continue;
      const rx = mkBtn('rx' + (mine.has(emoji) ? ' mine' : ''), '', () => this.toggleReaction(id, emoji));
      const e = document.createElement('span'); e.textContent = emoji; rx.appendChild(e);
      if (count > 1) { const c = document.createElement('span'); c.className = 'c'; c.textContent = String(count); rx.appendChild(c); }
      summary.appendChild(rx);
    }
  }
  flushSeen() {
    if (document.visibilityState !== 'visible' || !document.hasFocus()) return;
    for (const id of this.unseen) this.socket.emit('seen', { msgId: id });
    this.unseen.clear();
  }
  _onSeen({ msgId, senderId }) {
    if (senderId === this.selfId) return;
    const el = document.querySelector(`.msg[data-id="${CSS.escape(msgId)}"] .msg-status`);
    if (el) { el.textContent = 'seen ✓✓'; el.classList.add('seen'); }
  }
  _unsend(id) { this.socket.emit('delete', { msgId: id }); this._applyDelete(id); }
  _applyDelete(id) {
    this.msgStore.delete(id);
    const el = document.querySelector(`.msg[data-id="${CSS.escape(id)}"]`); if (!el) return;
    el.classList.remove('actions-open');
    ['.msg-actions', '.msg-reactions', '.msg-status'].forEach(sel => { const n = el.querySelector(sel); if (n) n.remove(); });
    const bubble = el.querySelector('.msg-bubble'); bubble.className = 'msg-bubble undecryptable'; bubble.textContent = '🚫 message unsent';
  }
  _onUsers(users) {
    const others = users.filter(u => u.id !== this.selfId).map(u => u.name);
    $('online-bar').textContent = others.length ? `online: ${others.join(', ')}` : 'no one else online';
  }
}

/* ============================ INIT ============================ */
function init() {
  const socket = io();
  const chat = new ChatUI(socket);
  const call = new CallManager(socket);
  const session = { me: '', selfId: '', baseKey: null, challenge: null, inChat: false };

  const showError = t => { const el = $('error-msg'); el.textContent = t || ''; el.style.display = t ? 'block' : 'none'; };
  const setConnected = ok => { $('conn-banner').classList.toggle('show', !ok); $('conn-dot').classList.toggle('offline', !ok); };
  function enterChat() {
    if (session.inChat) return;
    session.inChat = true; $('lobby').style.display = 'none'; $('chat').style.display = 'flex';
    $('header-user').textContent = 'logged in as ' + session.me; $('msg-input').focus();
  }
  async function joinRoom() {
    const u = $('username').value.trim(), p = $('password').value;
    if (!u || !p) return;
    if (!session.challenge) { showError('connecting… try again in a moment'); return; }
    const btn = $('enter-btn'); btn.disabled = true; btn.textContent = 'verifying…'; showError('');
    try {
      session.baseKey = await deriveBaseKey(p);
      chat.setMsgKey(await deriveMsgKey(session.baseKey));
      session.me = u;
      socket.emit('join', { username: u, response: await authResponse(session.baseKey, session.challenge) });
    } catch (e) { showError('something went wrong — try again'); btn.disabled = false; btn.textContent = 'enter →'; }
  }

  socket.on('challenge', async c => {
    session.challenge = c;
    if (session.inChat && session.baseKey && session.me) { try { socket.emit('join', { username: session.me, response: await authResponse(session.baseKey, c) }); } catch (e) {} }
  });
  socket.on('joined', ({ selfId, name }) => { session.selfId = selfId; session.me = name; chat.setSelfId(selfId); setConnected(true); enterChat(); chat.flushSeen(); });
  socket.on('auth_error', ({ reason, retryInMs } = {}) => {
    if (session.inChat) return;
    const btn = $('enter-btn'); btn.disabled = false; btn.textContent = 'enter →';
    if (reason === 'locked' || (retryInMs && retryInMs > 0)) showError(`too many attempts — locked for ${Math.ceil((retryInMs || 0) / 1000)}s`);
    else showError('wrong password — try again');
  });
  socket.on('disconnect', () => { if (session.inChat) setConnected(false); });

  chat.wire();
  $('enter-btn').addEventListener('click', joinRoom);
  $('password').addEventListener('keydown', e => { if (e.key === 'Enter') joinRoom(); });
  $('username').addEventListener('keydown', e => { if (e.key === 'Enter') $('password').focus(); });
  $('leave-btn').addEventListener('click', () => location.reload());
  $('voice-btn').addEventListener('click', () => call.start('audio'));
  $('video-btn').addEventListener('click', () => call.start('video'));
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

})();
