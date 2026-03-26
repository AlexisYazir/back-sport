/* eslint-disable */
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';

@Injectable()
export class R2StorageService {
  private readonly s3: S3Client;

  constructor(private readonly configService: ConfigService) {
    this.s3 = new S3Client({
      region: 'auto',
      endpoint: this.configService.get<string>('R2_ENDPOINT')!,
      credentials: {
        accessKeyId: this.configService.get<string>('R2_ACCESS_KEY_ID')!,
        secretAccessKey: this.configService.get<string>('R2_SECRET_ACCESS_KEY')!,
      },
    });
  }

  private get bucket(): string {
    return this.configService.get<string>('R2_BUCKET')!;
  }

  async uploadBuffer(key: string, body: Buffer, contentType = 'application/octet-stream') {
    await this.s3.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: contentType,
      }),
    );
  }

  async uploadText(key: string, content: string, contentType = 'text/plain; charset=utf-8') {
    await this.uploadBuffer(key, Buffer.from(content, 'utf8'), contentType);
  }

  async list(prefix?: string) {
    const response = await this.s3.send(
      new ListObjectsV2Command({
        Bucket: this.bucket,
        Prefix: prefix,
      }),
    );

    return response.Contents ?? [];
  }

  async downloadStream(key: string) {
    const result = await this.s3.send(
      new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
      }),
    );

    return result.Body;
  }

  async downloadText(key: string): Promise<string> {
    const body: any = await this.downloadStream(key);
    if (body?.transformToString) {
      return body.transformToString();
    }

    const chunks: Buffer[] = [];
    for await (const chunk of body) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks).toString('utf8');
  }

  async delete(key: string) {
    await this.s3.send(
      new DeleteObjectCommand({
        Bucket: this.bucket,
        Key: key,
      }),
    );
  }
}
