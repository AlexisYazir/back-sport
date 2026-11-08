import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

@Injectable()
export class DeletionSecrets {
  constructor(private readonly config: ConfigService) {}
  private key(purpose: string): Buffer {
    const secret = this.config.get<string>('ACCOUNT_DELETION_SECRET') ?? '';
    if (
      !/^[a-f\d]{64}$/i.test(secret) ||
      [
        'JWT_SECRET',
        'JWT_REFRESH_SECRET',
        'ACCOUNT_DELETION_LEDGER_SECRET',
      ].some(
        (name) =>
          secret.toLowerCase() === this.config.get<string>(name)?.toLowerCase(),
      )
    )
      throw new ServiceUnavailableException(
        'La eliminación de cuentas no está configurada',
      );
    return createHmac('sha256', Buffer.from(secret, 'hex'))
      .update(purpose)
      .digest();
  }
  hash(purpose: string, id: string, value: string): string {
    return createHmac('sha256', this.key(purpose))
      .update(id)
      .update('\0')
      .update(value)
      .digest('hex');
  }
  matches(
    purpose: string,
    id: string,
    value: string,
    expected: string | null,
  ): boolean {
    return (
      !!expected &&
      /^[a-f\d]{64}$/.test(expected) &&
      timingSafeEqual(
        Buffer.from(this.hash(purpose, id, value), 'hex'),
        Buffer.from(expected, 'hex'),
      )
    );
  }
  encrypt(value: string): string {
    const iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', this.key('notification'), iv);
    const bytes = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return [iv, cipher.getAuthTag(), bytes]
      .map((part) => part.toString('base64url'))
      .join('.');
  }
  decrypt(value: string): string {
    const parts = value.split('.');
    if (parts.length !== 3)
      throw new Error('ACCOUNT_DELETION_NOTIFICATION_INVALID');
    const [iv, tag, bytes] = parts.map((part) =>
      Buffer.from(part, 'base64url'),
    );
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.key('notification'),
      iv,
    );
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(bytes), decipher.final()]).toString(
      'utf8',
    );
  }
}
