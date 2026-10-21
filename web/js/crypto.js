// Client-side crypto. Wire format follows PrivateBin v2:
// adata = [[iv, salt, iterations, keysize, tagsize, "aes", "gcm", compression], format, opendiscussion, burn]
// ct = base64(AES-256-GCM(PBKDF2-SHA256(key || password), JSON.stringify(adata) as AAD)).
// The random key lives only in the URL fragment (base58).
"use strict";
(function () {
  const ITERATIONS = 600000, KEY_BYTES = 32, TAG_BITS = 128, IV_BYTES = 12, SALT_BYTES = 8;
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const enc = new TextEncoder(), dec = new TextDecoder();

  const b64 = (u8) => {
    let s = "";
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

  function b58encode(bytes) {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    let out = "";
    while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
    for (const b of bytes) { if (b !== 0) break; out = "1" + out; }
    return out;
  }
  function b58decode(s) {
    let n = 0n;
    for (const ch of s) {
      const i = B58.indexOf(ch);
      if (i < 0) throw new Error("bad key");
      n = n * 58n + BigInt(i);
    }
    const bytes = [];
    while (n > 0n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
    let zeros = 0;
    for (const ch of s) { if (ch !== "1") break; zeros++; }
    return Uint8Array.from([...new Array(zeros).fill(0), ...bytes]);
  }

  async function deriveKey(keyBytes, password, salt, iterations) {
    const pw = enc.encode(password || "");
    const material = new Uint8Array(keyBytes.length + pw.length);
    material.set(keyBytes); material.set(pw, keyBytes.length);
    const base = await crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, base,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  async function pipe(data, stream) {
    const out = new Blob([data]).stream().pipeThrough(stream);
    return new Uint8Array(await new Response(out).arrayBuffer());
  }
  const canDeflate = typeof CompressionStream === "function";

  async function encrypt(text, format, burn, password) {
    let plain = enc.encode(JSON.stringify({ paste: text }));
    let compression = "none";
    if (canDeflate) { plain = await pipe(plain, new CompressionStream("deflate-raw")); compression = "zlib"; }
    const keyBytes = rand(KEY_BYTES), iv = rand(IV_BYTES), salt = rand(SALT_BYTES);
    const adata = [[b64(iv), b64(salt), ITERATIONS, 256, TAG_BITS, "aes", "gcm", compression], format, 0, burn ? 1 : 0];
    const key = await deriveKey(keyBytes, password, salt, ITERATIONS);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(JSON.stringify(adata)), tagLength: TAG_BITS }, key, plain);
    return { keyB58: b58encode(keyBytes), body: { v: 2, adata, ct: b64(new Uint8Array(ct)) } };
  }

  async function decrypt(paste, keyB58, password) {
    const [params, format] = paste.adata;
    const [iv, salt, iterations, , tagBits, , , compression] = params;
    const key = await deriveKey(b58decode(keyB58), password, unb64(salt), iterations);
    let plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(iv), additionalData: enc.encode(JSON.stringify(paste.adata)), tagLength: tagBits },
      key, unb64(paste.ct)));
    if (compression === "zlib") plain = await pipe(plain, new DecompressionStream("deflate-raw"));
    return { text: JSON.parse(dec.decode(plain)).paste, format };
  }

  window.PasteCrypto = { encrypt, decrypt };
})();
