/**
 * Utility functions for encrypting and decrypting sensitive data (like API keys) using the Web Crypto API.
 * The encryption key is generated once per device and stored securely in localStorage, ensuring that
 * sensitive data remains protected even if the vault is compromised. This approach balances security
 * with usability, as users won't need to re-enter their API keys on every plugin load.
 *
 * Note: This encryption is meant to protect against casual snooping and is not a substitute for
 * enterprise-grade security solutions. Always follow best practices for handling sensitive data.
 */
const LOCAL_STORAGE_KEY = 'vulndash-encryption-key';
export const ENCRYPTED_SECRET_PREFIX = 'enc:';

export interface DecryptSecretResult {
  status: 'empty' | 'success' | 'failed';
  value: string;
  reason?: 'invalid_payload' | 'decrypt_failed';
}

async function getOrCreateKey(): Promise<CryptoKey> {
  let rawKey = window.localStorage.getItem(LOCAL_STORAGE_KEY);

  if (!rawKey) {
    // Generate a new AES-GCM key if one doesn't exist on this device
    const key = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const exported = await window.crypto.subtle.exportKey('raw', key);

    // Store the raw key securely in local storage (outside the vault)
    rawKey = btoa(String.fromCharCode(...new Uint8Array(exported)));
    window.localStorage.setItem(LOCAL_STORAGE_KEY, rawKey);
    return key;
  }

  const keyBytes = Uint8Array.from(atob(rawKey), c => c.charCodeAt(0));
  return window.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptSecret(plainText: string): Promise<string> {
  if (!plainText) return '';
  const key = await getOrCreateKey();

  // Create a random Initialization Vector
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plainText);

  const cipherText = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );

  // Combine the IV and Ciphertext into a single storable string
  const combined = new Uint8Array(iv.length + cipherText.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherText), iv.length);
  return btoa(String.fromCharCode(...combined));
}

export async function decryptSecret(cipherTextB64: string): Promise<DecryptSecretResult> {
  if (!cipherTextB64) {
    return { status: 'empty', value: '' };
  }

  try {
    const key = await getOrCreateKey();
    const combined = Uint8Array.from(atob(cipherTextB64), c => c.charCodeAt(0));
    if (combined.length <= 12) {
      return {
        status: 'failed',
        value: '',
        reason: 'invalid_payload'
      };
    }

    const iv = combined.slice(0, 12);
    const cipherText = combined.slice(12);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      cipherText
    );
    return { status: 'success', value: new TextDecoder().decode(decrypted) };
  } catch {
    console.warn("VulnDash: Failed to decrypt secret. You may need to re-enter your API keys.");
    return {
      status: 'failed',
      value: '',
      reason: 'decrypt_failed'
    };
  }
}
