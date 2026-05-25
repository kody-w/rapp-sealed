// Conformance check for rapp-sealed/1.0 — run: `node verify.mjs`
// Verifies the codec against the deterministic vectors (KDF + AES-GCM) and a live round-trip,
// plus tamper- and wrong-key-rejection. Exit 0 = conformant.
import { readFileSync } from 'node:fs';
import { seal, open, SALT, ITERATIONS } from './rapp_sealed.mjs';

const V = JSON.parse(readFileSync(new URL('./test-vectors.json', import.meta.url)));
const enc = new TextEncoder();
const hex = u8 => [...new Uint8Array(u8)].map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
let ok = true; const pass = (n, c) => { console.log((c ? 'PASS ' : 'FAIL ') + n); ok = ok && c; };

// 1) scheme params match the spec
pass('salt = rapp-neighborhood-5a/1', SALT === V.kdf.salt && SALT === 'rapp-neighborhood-5a/1');
pass('iterations = 210000', ITERATIONS === V.kdf.iterations && ITERATIONS === 210000);

// 2) PBKDF2-SHA256 derives the vector's 256-bit key
const base = await crypto.subtle.importKey('raw', enc.encode(V.kdf.secret), 'PBKDF2', false, ['deriveBits']);
const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(V.kdf.salt), iterations: V.kdf.iterations, hash: 'SHA-256' }, base, 256);
pass('PBKDF2 derived key matches vector', hex(bits) === V.kdf.derived_key_256_hex);

// 3) AES-256-GCM (fixed key+IV) reproduces the vector ciphertext+tag
const key = await crypto.subtle.importKey('raw', new Uint8Array(bits), { name: 'AES-GCM' }, false, ['encrypt']);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fromHex(V.aes_gcm.iv_hex) }, key, enc.encode(V.aes_gcm.plaintext));
pass('AES-GCM ciphertext+tag matches vector', hex(ct) === V.aes_gcm.ciphertext_with_tag_hex);

// 4) live round-trip (random IV)
const msg = { schema: 'rapp-twin-chat/1.0', kind: 'say', payload: { text: 'hello 🪁' } };
const sealed = await seal('s3cret', msg);
pass('seal -> {schema:rapp-sealed/1.0, iv, ct}', sealed.schema === 'rapp-sealed/1.0' && !!sealed.iv && !!sealed.ct);
pass('open(seal(x)) === x', JSON.stringify(await open('s3cret', sealed)) === JSON.stringify(msg));

// 5) tamper + wrong key are rejected
let tampered = { ...sealed, ct: sealed.ct.slice(0, 10) + (sealed.ct[10] === 'A' ? 'B' : 'A') + sealed.ct.slice(11) };
let threw = false; try { await open('s3cret', tampered); } catch (e) { threw = true; }
pass('tampered ciphertext rejected', threw);
threw = false; try { await open('WRONG', sealed); } catch (e) { threw = true; }
pass('wrong key rejected', threw);

console.log(ok ? '\nrapp-sealed/1.0: CONFORMANT ✅' : '\nrapp-sealed/1.0: NON-CONFORMANT ❌');
process.exit(ok ? 0 : 1);
