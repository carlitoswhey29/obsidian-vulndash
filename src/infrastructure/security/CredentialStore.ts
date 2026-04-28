import {
  decryptSecret,
  ENCRYPTED_SECRET_PREFIX,
  encryptSecret,
  type DecryptSecretResult
} from './crypto';

export interface StoredCredentialResult {
  readonly decryptionFailed: boolean;
  readonly needsMigration: boolean;
  readonly value: string;
}

export interface CredentialCipher {
  decrypt(cipherTextB64: string): Promise<DecryptSecretResult>;
  encrypt(plainText: string): Promise<string>;
}

const DEFAULT_CIPHER: CredentialCipher = {
  decrypt: decryptSecret,
  encrypt: encryptSecret
};

export class CredentialStore {
  public constructor(
    private readonly cipher: CredentialCipher = DEFAULT_CIPHER,
    private readonly encryptedSecretPrefix = ENCRYPTED_SECRET_PREFIX
  ) {}

  public async read(storedSecret: string): Promise<StoredCredentialResult> {
    if (!storedSecret) {
      return { decryptionFailed: false, needsMigration: false, value: '' };
    }

    if (!storedSecret.startsWith(this.encryptedSecretPrefix)) {
      return { decryptionFailed: false, needsMigration: true, value: storedSecret };
    }

    const encryptedPayload = storedSecret.slice(this.encryptedSecretPrefix.length);
    const decrypted = await this.cipher.decrypt(encryptedPayload);
    if (decrypted.status === 'success') {
      return { decryptionFailed: false, needsMigration: false, value: decrypted.value };
    }

    return { decryptionFailed: true, needsMigration: false, value: '' };
  }

  public async serialize(secret: string): Promise<string> {
    if (!secret) {
      return '';
    }

    const encrypted = await this.cipher.encrypt(secret);
    if (!encrypted) {
      return '';
    }

    return `${this.encryptedSecretPrefix}${encrypted}`;
  }
}
