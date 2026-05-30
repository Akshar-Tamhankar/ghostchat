# ghostchat

Private real-time chat for two — end-to-end encrypted, with ephemeral voice/video calls.

## Run
```
npm install
ROOM_PASSWORD="your-strong-password" npm start   # default port 3000
```
Deploy behind HTTPS/TLS (Render provides it). Calls (camera/mic) require a secure context.

## Architecture
ES modules under `public/js/`:
- `crypto.js` — PBKDF2 key derivation, challenge-response auth, AES-GCM message encryption (pure functions)
- `calls.js`  — `CallManager`: WebRTC lifecycle, screen share, bandwidth tuning, ICE-restart recovery
- `chat.js`   — `ChatUI`: messaging, reactions, reply, typing, read receipts, unsend
- `main.js`   — entry point: session/auth, reconnect, composes the above
`server.js` is a thin signaling + static relay; it never sees plaintext or media.

## Security
- Password never transmitted: HMAC-over-challenge auth, constant-time verify, per-IP brute-force lockout.
- Messages AES-GCM-256 encrypted client-side; server relays ciphertext only.
- Calls are P2P; the server relays only SDP/ICE. Nothing recorded or stored.
- Strict CSP (module scripts only), same-origin CORS, textContent rendering, server-side input whitelists.

## Features
- Messaging, presence, typing, reply, reactions (❤️ 🥀 💀), read receipts (sent → seen)
- Unsend (deletes the bubble on both sides)
- Auto-reconnect: silently re-auths/re-joins after dropped sockets
- Voice + video calls — mic & camera start MUTED; tap to enable
- Screen sharing (video calls), via live track replacement (no renegotiation)
- Calls survive signaling blips and recover broken media paths via ICE restart (15s grace)
- Video tuned to 720p@30 capped ~1.2 Mbps; audio uses echo-cancel / noise-suppress / AGC
- Mobile: dvh layout, 16px inputs (no iOS focus-zoom), safe-area insets, tap-to-reveal message actions
- Send pop animation, reaction pop-in, reduced-motion support

## Limits
- Calls use public STUN only; restrictive/symmetric-NAT networks need a TURN relay (not included).
- Screen share is available in video calls. 2-person room. No message persistence (refresh clears history).
