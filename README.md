# rapp-sealed

**`rapp-sealed/1.0`** — the canonical end‑to‑end sealed‑envelope codec for the RAPP neighborhood.
One reference implementation + conformance vectors, so every place that seals (e.g. the browser
vBrainstem, the bridge, the CLI, Node, the rapp-mcp host) speaks **exactly** the same bytes and
can't silently drift. The codec is **transport‑agnostic** — any caller that reaches the brainstem
seals with it; the authoritative enumeration of transports lives in
[rapp-neighborhood-protocol](https://github.com/kody-w/rapp-neighborhood-protocol) §5.

> Treat the wire — broker, TURN, relays, the whole network — as **fully untrusted**. A sealed
> message reveals nothing and can't be forged. The secret travels only in the out‑of‑band pairing
> link/QR, never to a server. This is what makes a relayed channel *as secure as on‑device.*

## The scheme

```
key  = PBKDF2-SHA256(secret, salt="rapp-neighborhood-5a/1", 210000 iterations) → AES-256-GCM
wire = { "schema":"rapp-sealed/1.0", "iv":<base64url, 12 bytes>, "ct":<base64url, ciphertext+tag> }
```

- **Confidential** (AES‑256‑GCM), **tamper‑evident** (GCM auth tag), **authenticated** by
  key‑possession (a wrong‑key peer can't read or forge — it can't even read the rejection).
- **base64url**, no padding. Random 12‑byte IV per message.
- Replay protection (a `nonce` + `utc`) lives in the *envelope* you seal, not in this layer.

## Use it

```js
import { seal, open } from './rapp_sealed.mjs';   // browser or Node — Web Crypto, no deps
const sealed = await seal(secret, { schema:'rapp-twin-chat/1.0', kind:'say', payload:{ text:'hi' } });
// → { schema:'rapp-sealed/1.0', iv, ct }   ship it over any transport
const msg = await open(secret, sealed);            // throws on wrong key or tamper
```

## Conformance

`test-vectors.json` pins the KDF (a known secret → known 256‑bit key) and an AES‑GCM vector
(fixed key+IV → fixed ciphertext+tag), so any implementation in any language can self‑check.

```
node verify.mjs        # → rapp-sealed/1.0: CONFORMANT ✅  (KDF, AES-GCM, round-trip, tamper, wrong-key)
```

An implementation conforms if it reproduces the vectors and round‑trips `open(seal(x)) === x`.

Part of [rapp-neighborhood-protocol](https://github.com/kody-w/rapp-neighborhood-protocol) (§8).
MIT © Kody Wildfeuer.
