// rapp-sealed/1.0 — end-to-end sealed envelopes for the RAPP neighborhood.
//
// The canonical reference codec. Runs identically in the browser and in Node (Web Crypto).
// Treat the wire (broker, TURN, relays, network) as fully untrusted: a sealed message reveals
// nothing and can't be forged. The secret travels ONLY in the out-of-band pairing link/QR —
// never to a server. See NEIGHBORHOOD_PROTOCOL.md §8.
//
//   key   = PBKDF2-SHA256(secret, salt="rapp-neighborhood-5a/1", 210000 iters) → AES-256-GCM
//   wire  = { schema:"rapp-sealed/1.0", iv:<base64url 12 bytes>, ct:<base64url ciphertext+tag> }
//   auth  = key-possession (a wrong-key peer can't read or forge); replay-guard with a nonce/utc
//           inside the sealed payload (envelope-level, not this layer's concern).

export const SALT = 'rapp-neighborhood-5a/1';
export const ITERATIONS = 210000;

const _b64url   = u8 => btoa(String.fromCharCode.apply(null, u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const _unb64url = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };

const _cache = {};
export async function channelKey(secret) {
  if (!secret) throw new Error('rapp-sealed: a secret is required');
  if (_cache[secret]) return _cache[secret];
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(SALT), iterations: ITERATIONS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return (_cache[secret] = key);
}

// seal(secret, obj) -> { schema:'rapp-sealed/1.0', iv, ct }   (random 12-byte IV)
export async function seal(secret, obj) {
  const key = await channelKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { schema: 'rapp-sealed/1.0', iv: _b64url(iv), ct: _b64url(new Uint8Array(ct)) };
}

// open(secret, sealed) -> obj   (throws if the key is wrong OR the ciphertext was tampered with)
export async function open(secret, sealed) {
  if (!sealed || sealed.schema !== 'rapp-sealed/1.0') throw new Error('rapp-sealed: not a sealed envelope');
  const key = await channelKey(secret);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _unb64url(sealed.iv) }, key, _unb64url(sealed.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

export const _b64 = { encode: _b64url, decode: _unb64url };   // exported for parity tests
