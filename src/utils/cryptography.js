/**
 * Al-Kantara Security — Cryptography Utility
 * AES-256-GCM encryption for log export using Web Crypto API.
 * No external dependencies. PBKDF2 key derivation (600k iterations).
 *
 * © Urbanyl — github.com/urbanyl
 */

(function () {
  "use strict";

  const AKSCrypto = {
    MAGIC: new Uint8Array([0x41, 0x4B, 0x53, 0x01]),

    async deriveKey(passphrase, salt) {
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(passphrase),
        "PBKDF2",
        false,
        ["deriveKey"]
      );
      return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    },

    async encrypt(plaintext, passphrase) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await this.deriveKey(passphrase, salt);

      const encoded = new TextEncoder().encode(plaintext);
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoded
      );

      const result = new Uint8Array(4 + 2 + 2 + salt.length + iv.length + ciphertext.byteLength);
      const view = new DataView(result.buffer);
      result.set(this.MAGIC, 0);
      view.setUint32(4, salt.length, false);
      view.setUint32(8, iv.length, false);
      result.set(salt, 12);
      result.set(iv, 12 + salt.length);
      result.set(new Uint8Array(ciphertext), 12 + salt.length + iv.length);

      return result;
    },

    async decrypt(data, passphrase) {
      const arr = new Uint8Array(data);

      const magic = arr.slice(0, 4);
      if (magic[0] !== this.MAGIC[0] || magic[1] !== this.MAGIC[1] ||
          magic[2] !== this.MAGIC[2] || magic[3] !== this.MAGIC[3]) {
        throw new Error("Invalid AKS encryption header");
      }

      const view = new DataView(arr.buffer);
      const saltLen = view.getUint32(4, false);
      const ivLen   = view.getUint32(8, false);

      const salt = arr.slice(12, 12 + saltLen);
      const iv   = arr.slice(12 + saltLen, 12 + saltLen + ivLen);
      const ciphertext = arr.slice(12 + saltLen + ivLen);

      const key = await this.deriveKey(passphrase, salt);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
      );

      return new TextDecoder().decode(decrypted);
    },

    async hashSHA256(data) {
      const encoded = typeof data === "string" ? new TextEncoder().encode(data) : data;
      const hash = await crypto.subtle.digest("SHA-256", encoded);
      return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
    },

    generateChecksum(payload) {
      let hash = 0x811c9dc5;
      const str = typeof payload === "string" ? payload : JSON.stringify(payload);
      for (let i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i);
        hash = (hash * 0x01000193) >>> 0;
      }
      return hash.toString(16).toUpperCase().padStart(8, "0");
    }
  };

  if (typeof window !== "undefined") {
    window.AKSCrypto = AKSCrypto;
  }
})();
