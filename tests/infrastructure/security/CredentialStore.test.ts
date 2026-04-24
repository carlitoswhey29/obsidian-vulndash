import assert from 'node:assert/strict';
import test from 'node:test';
import { CredentialStore, type CredentialCipher } from '../../../src/infrastructure/security/CredentialStore';
import type { DecryptSecretResult } from '../../../src/infrastructure/security/crypto';

class FakeCredentialCipher implements CredentialCipher {
  private readonly decryptResultByCipherText: Record<string, DecryptSecretResult>;
  private readonly encryptedValue: string;

  public constructor(options: {
    decryptResultByCipherText?: Record<string, DecryptSecretResult>;
    encryptedValue?: string;
  } = {}) {
    this.decryptResultByCipherText = options.decryptResultByCipherText ?? {};
    this.encryptedValue = options.encryptedValue ?? 'ciphertext';
  }

  public async decrypt(cipherTextB64: string): Promise<DecryptSecretResult> {
    return this.decryptResultByCipherText[cipherTextB64] ?? { status: 'failed', value: '', reason: 'decrypt_failed' };
  }

  public async encrypt(_plainText: string): Promise<string> {
    return this.encryptedValue;
  }
}

test('CredentialStore serializes non-empty secrets with the encrypted prefix', async () => {
  const store = new CredentialStore(new FakeCredentialCipher({ encryptedValue: 'cipher-123' }));

  assert.equal(await store.serialize('top-secret'), 'enc:cipher-123');
});

test('CredentialStore reads encrypted secrets through the cipher', async () => {
  const store = new CredentialStore(new FakeCredentialCipher({
    decryptResultByCipherText: {
      'cipher-123': { status: 'success', value: 'top-secret' }
    }
  }));

  assert.deepEqual(await store.read('enc:cipher-123'), {
    decryptionFailed: false,
    needsMigration: false,
    value: 'top-secret'
  });
});

test('CredentialStore preserves plaintext stored secrets for migration', async () => {
  const store = new CredentialStore(new FakeCredentialCipher());

  assert.deepEqual(await store.read('legacy-secret'), {
    decryptionFailed: false,
    needsMigration: true,
    value: 'legacy-secret'
  });
});

test('CredentialStore returns an empty value for absent secrets', async () => {
  const store = new CredentialStore(new FakeCredentialCipher());

  assert.deepEqual(await store.read(''), {
    decryptionFailed: false,
    needsMigration: false,
    value: ''
  });
  assert.equal(await store.serialize(''), '');
});

test('CredentialStore fails safely when decrypting invalid encrypted secrets', async () => {
  const store = new CredentialStore(new FakeCredentialCipher({
    decryptResultByCipherText: {
      broken: { status: 'failed', value: '', reason: 'decrypt_failed' }
    }
  }));

  assert.deepEqual(await store.read('enc:broken'), {
    decryptionFailed: true,
    needsMigration: false,
    value: ''
  });
});
