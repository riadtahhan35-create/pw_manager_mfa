/* frontend/srp/srp.js
   SRP-6a client (RFC 5054-ish) tuned to match pysrp behavior:
   - Hash: SHA-1
   - Group: 2048-bit (NG_2048)
   - Important: hashing uses MINIMAL big-int bytes (no fixed padding),
     which matches many SRP libs including pysrp.
*/

(function () {
  "use strict";

  // ===== NG_2048 (RFC 5054) =====
  const N_HEX =
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07" +
    "FC3192943DB56050A37329CBB4A099ED8193E0757767A13D" +
    "D52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0" +
    "CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA7" +
    "1D281E446B14773BCA97B43A23FB801676BD207A436C6481" +
    "F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
    "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C382" +
    "71AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F5475" +
    "9B65E372FCD68EF20FA7111F9E4AFF73";

  const N = BigInt("0x" + N_HEX);
  const g = 2n;

  // ========= bytes/base64 =========
  function utf8Bytes(s) {
    return new TextEncoder().encode(s);
  }

  function hexToBytes(hex) {
    const clean = hex.replace(/^0x/, "");
    if (clean.length % 2) throw new Error("Invalid hex");
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function bytesToHex(u8) {
    return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  function concatBytes(...parts) {
    const total = parts.reduce((s, p) => s + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  }

  function bytesToB64(u8) {
    let s = "";
    for (const b of u8) s += String.fromCharCode(b);
    return btoa(s);
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToBigInt(u8) {
    if (!u8.length) return 0n;
    return BigInt("0x" + bytesToHex(u8));
  }

  function bigIntToBytesMinimal(x) {
    if (x === 0n) return new Uint8Array([0]);
    let hex = x.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    // remove leading 00 pairs (but keep at least one byte)
    while (hex.startsWith("00") && hex.length > 2) hex = hex.slice(2);
    return hexToBytes(hex);
  }

  // ========= SHA1 =========
  async function sha1(u8) {
    const buf = await crypto.subtle.digest("SHA-1", u8);
    return new Uint8Array(buf);
  }

  async function H(...parts) {
    return sha1(concatBytes(...parts));
  }

  function xorBytes(a, b) {
    if (a.length !== b.length) throw new Error("xor mismatch");
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  // ========= modPow =========
  function modPow(base, exp, mod) {
    let r = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % mod;
      b = (b * b) % mod;
      e >>= 1n;
    }
    return r;
  }

  // ========= SRP computations (minimal-bytes hashing) =========
  async function compute_k() {
    // k = H(N || g)  (minimal bytes)
    return bytesToBigInt(await H(bigIntToBytesMinimal(N), bigIntToBytesMinimal(g)));
  }

  async function compute_x(I, P, saltBytes) {
    // x = H(salt || H(I ":" P))
    const inner = await H(utf8Bytes(`${I}:${P}`));
    return bytesToBigInt(await H(saltBytes, inner));
  }

  async function compute_u(A, B) {
    // u = H(A || B) (minimal bytes)
    return bytesToBigInt(await H(bigIntToBytesMinimal(A), bigIntToBytesMinimal(B)));
  }

  async function compute_K(S) {
    // K = H(S) (minimal bytes)
    return H(bigIntToBytesMinimal(S)); // bytes
  }

  async function compute_M1(I, saltBytes, A, B, K_bytes) {
    // M1 = H( H(N) xor H(g) || H(I) || s || A || B || K )
    const HN = await H(bigIntToBytesMinimal(N));
    const Hg = await H(bigIntToBytesMinimal(g));
    const Hxor = xorBytes(HN, Hg);
    const HI = await H(utf8Bytes(I));

    return H(
      Hxor,
      HI,
      saltBytes,
      bigIntToBytesMinimal(A),
      bigIntToBytesMinimal(B),
      K_bytes
    );
  }

  async function compute_HAMK(A, M1_bytes, K_bytes) {
    // HAMK = H(A || M1 || K)
    return H(bigIntToBytesMinimal(A), M1_bytes, K_bytes);
  }

  function randomBigInt(bytesLen = 32) {
    const u8 = new Uint8Array(bytesLen);
    crypto.getRandomValues(u8);
    u8[0] |= 1;
    return bytesToBigInt(u8);
  }

  class Client {
    constructor(username, password) {
      if (!username || !password) throw new Error("Missing username/password");
      this.I = username;
      this.P = password;
      this.a = null;
      this.A = null;
      this.saltBytes = null;
      this.B = null;
      this.K = null;
      this.M1 = null;
      this.HAMK = null;
    }

    async start() {
      this.a = randomBigInt(32);
      this.A = modPow(g, this.a, N);

      // IMPORTANT: send A minimal bytes (matches pysrp)
      const A_bytes = bigIntToBytesMinimal(this.A);
      return { A_b64: bytesToB64(A_bytes) };
    }

    async processChallenge(salt_b64, B_b64) {
      if (!this.A || !this.a) throw new Error("Call start() first");

      this.saltBytes = b64ToBytes(salt_b64);
      this.B = bytesToBigInt(b64ToBytes(B_b64));

      if (this.B % N === 0n) throw new Error("Invalid SRP B");

      const k = await compute_k();
      const x = await compute_x(this.I, this.P, this.saltBytes);
      const u = await compute_u(this.A, this.B);

      const gx = modPow(g, x, N);
      let base = (this.B - (k * gx) % N) % N;
      if (base < 0n) base += N;

      // exp = a + u*x  (DO NOT MOD)  -> important for matching server
      const exp = this.a + u * x;

      const S = modPow(base, exp, N);

      this.K = await compute_K(S);
      this.M1 = await compute_M1(this.I, this.saltBytes, this.A, this.B, this.K);
      this.HAMK = await compute_HAMK(this.A, this.M1, this.K);

      return {
        M_b64: bytesToB64(this.M1),
        K_b64: bytesToB64(this.K),
        expected_server_proof_b64: bytesToB64(this.HAMK),
      };
    }

    verifyServerProof(server_proof_b64) {
      if (!this.HAMK) throw new Error("Call processChallenge() first");
      const got = b64ToBytes(server_proof_b64);
      const exp = this.HAMK;
      if (got.length !== exp.length) return false;
      for (let i = 0; i < got.length; i++) if (got[i] !== exp[i]) return false;
      return true;
    }
  }

  window.SRP = { Client };
})();
