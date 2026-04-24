// tests/infrastructure/security/CredentialStore.test.ts
import assert from "node:assert/strict";
import test from "node:test";

// src/infrastructure/security/crypto.ts
var LOCAL_STORAGE_KEY = "vulndash-encryption-key";
var ENCRYPTED_SECRET_PREFIX = "enc:";
async function getOrCreateKey() {
  let rawKey = window.localStorage.getItem(LOCAL_STORAGE_KEY);
  if (!rawKey) {
    const key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const exported = await window.crypto.subtle.exportKey("raw", key);
    rawKey = btoa(String.fromCharCode(...new Uint8Array(exported)));
    window.localStorage.setItem(LOCAL_STORAGE_KEY, rawKey);
    return key;
  }
  const keyBytes = Uint8Array.from(atob(rawKey), (c) => c.charCodeAt(0));
  return window.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptSecret(plainText) {
  if (!plainText) return "";
  const key = await getOrCreateKey();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plainText);
  const cipherText = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );
  const combined = new Uint8Array(iv.length + cipherText.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherText), iv.length);
  return btoa(String.fromCharCode(...combined));
}
async function decryptSecret(cipherTextB64) {
  if (!cipherTextB64) {
    return { status: "empty", value: "" };
  }
  try {
    const key = await getOrCreateKey();
    const combined = Uint8Array.from(atob(cipherTextB64), (c) => c.charCodeAt(0));
    if (combined.length <= 12) {
      return {
        status: "failed",
        value: "",
        reason: "invalid_payload"
      };
    }
    const iv = combined.slice(0, 12);
    const cipherText = combined.slice(12);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipherText
    );
    return { status: "success", value: new TextDecoder().decode(decrypted) };
  } catch {
    console.warn("VulnDash: Failed to decrypt secret. You may need to re-enter your API keys.");
    return {
      status: "failed",
      value: "",
      reason: "decrypt_failed"
    };
  }
}

// src/infrastructure/security/CredentialStore.ts
var DEFAULT_CIPHER = {
  decrypt: decryptSecret,
  encrypt: encryptSecret
};
var CredentialStore = class {
  constructor(cipher = DEFAULT_CIPHER, encryptedSecretPrefix = ENCRYPTED_SECRET_PREFIX) {
    this.cipher = cipher;
    this.encryptedSecretPrefix = encryptedSecretPrefix;
  }
  async read(storedSecret) {
    if (!storedSecret) {
      return { decryptionFailed: false, needsMigration: false, value: "" };
    }
    if (!storedSecret.startsWith(this.encryptedSecretPrefix)) {
      return { decryptionFailed: false, needsMigration: true, value: storedSecret };
    }
    const encryptedPayload = storedSecret.slice(this.encryptedSecretPrefix.length);
    const decrypted = await this.cipher.decrypt(encryptedPayload);
    if (decrypted.status === "success") {
      return { decryptionFailed: false, needsMigration: false, value: decrypted.value };
    }
    return { decryptionFailed: true, needsMigration: false, value: "" };
  }
  async serialize(secret) {
    if (!secret) {
      return "";
    }
    const encrypted = await this.cipher.encrypt(secret);
    if (!encrypted) {
      return "";
    }
    return `${this.encryptedSecretPrefix}${encrypted}`;
  }
};

// tests/infrastructure/security/CredentialStore.test.ts
var FakeCredentialCipher = class {
  constructor(options = {}) {
    this.decryptResultByCipherText = options.decryptResultByCipherText ?? {};
    this.encryptedValue = options.encryptedValue ?? "ciphertext";
  }
  async decrypt(cipherTextB64) {
    return this.decryptResultByCipherText[cipherTextB64] ?? { status: "failed", value: "", reason: "decrypt_failed" };
  }
  async encrypt(_plainText) {
    return this.encryptedValue;
  }
};
test("CredentialStore serializes non-empty secrets with the encrypted prefix", async () => {
  const store = new CredentialStore(new FakeCredentialCipher({ encryptedValue: "cipher-123" }));
  assert.equal(await store.serialize("top-secret"), "enc:cipher-123");
});
test("CredentialStore reads encrypted secrets through the cipher", async () => {
  const store = new CredentialStore(new FakeCredentialCipher({
    decryptResultByCipherText: {
      "cipher-123": { status: "success", value: "top-secret" }
    }
  }));
  assert.deepEqual(await store.read("enc:cipher-123"), {
    decryptionFailed: false,
    needsMigration: false,
    value: "top-secret"
  });
});
test("CredentialStore preserves plaintext stored secrets for migration", async () => {
  const store = new CredentialStore(new FakeCredentialCipher());
  assert.deepEqual(await store.read("legacy-secret"), {
    decryptionFailed: false,
    needsMigration: true,
    value: "legacy-secret"
  });
});
test("CredentialStore returns an empty value for absent secrets", async () => {
  const store = new CredentialStore(new FakeCredentialCipher());
  assert.deepEqual(await store.read(""), {
    decryptionFailed: false,
    needsMigration: false,
    value: ""
  });
  assert.equal(await store.serialize(""), "");
});
test("CredentialStore fails safely when decrypting invalid encrypted secrets", async () => {
  const store = new CredentialStore(new FakeCredentialCipher({
    decryptResultByCipherText: {
      broken: { status: "failed", value: "", reason: "decrypt_failed" }
    }
  }));
  assert.deepEqual(await store.read("enc:broken"), {
    decryptionFailed: true,
    needsMigration: false,
    value: ""
  });
});
