import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Readable } from 'node:stream';
import {
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  type _Object,
} from '@aws-sdk/client-s3';
import { R2StorageService } from './r2-storage.service';

interface StorageReply {
  Contents?: _Object[];
  IsTruncated?: boolean;
  NextContinuationToken?: string;
  Body?: Readable;
}

const mockSend = jest.fn<Promise<StorageReply>, [unknown]>();
jest.mock('@aws-sdk/client-s3', () => {
  const actual =
    jest.requireActual<typeof import('@aws-sdk/client-s3')>(
      '@aws-sdk/client-s3',
    );
  return {
    ...actual,
    S3Client: jest.fn().mockImplementation(() => ({ send: mockSend })),
  };
});

describe('R2 legacy storage namespace and pagination', () => {
  let service: R2StorageService;
  beforeEach(() => {
    mockSend.mockReset().mockResolvedValue({});
    service = new R2StorageService(
      new ConfigService({
        R2_ENDPOINT: 'http://127.0.0.1:9',
        R2_ACCESS_KEY_ID: 'synthetic-qa',
        R2_SECRET_ACCESS_KEY: 'synthetic-qa',
        R2_BUCKET: 'synthetic-qa',
      }),
    );
  });

  it.each([
    'full/backup-2026-11-08_10-00-00/full_2026-11-08_10-00-00.dump',
    'critical/backup-2026-11-08_10-00-00/critical_2026-11-08_10-00-00.log',
    'logs/2026-11-08/users.log',
    'logsVacum/vacuum-2026-11-08_10-00-00/vacuum-2026-11-08_10-00-00.log',
  ])('preserves the existing object format %s', async (key) => {
    await service.uploadText(key, 'synthetic');
    expect(mockSend.mock.calls[0][0]).toBeInstanceOf(PutObjectCommand);
    expect((mockSend.mock.calls[0][0] as PutObjectCommand).input.Key).toBe(key);
    await service.downloadStream(key);
    expect(mockSend.mock.calls[1][0]).toBeInstanceOf(GetObjectCommand);
    await service.delete(key);
    expect(mockSend).toHaveBeenCalledTimes(3);
  });

  it.each([
    '',
    'account-deletion/head.json',
    'sportcenter/account-deletion/v1/journal.json',
    'private/head.log',
    'full',
    'full/folder',
    'full/folder/head.json',
    'full//data.dump',
    'full/../data.dump',
    'full/.hidden/data.dump',
    'full/folder/../data.dump',
    'full/folder%2Fjournal/data.dump',
    'full/folder/data.dump%00',
    'full\\folder\\data.dump',
    'logs/2026-11-08/../../head.log',
    'logs/2026-11-08/users.log\n',
  ])(
    'rejects disallowed object operations before storage access: %j',
    async (key) => {
      await expect(service.uploadText(key, 'data')).rejects.toBeInstanceOf(
        BadRequestException,
      );
      await expect(service.downloadText(key)).rejects.toBeInstanceOf(
        BadRequestException,
      );
      await expect(service.delete(key)).rejects.toBeInstanceOf(
        BadRequestException,
      );
      expect(mockSend).not.toHaveBeenCalled();
    },
  );

  it.each([
    undefined,
    '',
    '/',
    'full',
    'account-deletion/',
    'private/',
    'full/../',
    'full/folder/nested/',
    'logs/%2E%2E/',
  ])('never lists a broad or reserved prefix: %j', async (prefix) => {
    await expect(service.list(prefix)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(mockSend).not.toHaveBeenCalled();
  });

  it('keeps every backup after the first 1000 results and sends continuation tokens', async () => {
    const first = Array.from({ length: 1000 }, (_, n) => ({
      Key: `full/folder-${n}/full.dump`,
    }));
    mockSend
      .mockResolvedValueOnce({
        Contents: first,
        IsTruncated: true,
        NextContinuationToken: 'synthetic-page-2',
      })
      .mockResolvedValueOnce({
        Contents: [
          { Key: 'full/last/full.dump' },
          { Key: 'account-deletion/head.json' },
          { Key: 'critical/another/critical.dump' },
          { Key: 'full/folder/unsafe.json' },
        ],
        IsTruncated: false,
      });
    const objects = await service.list('full/');
    expect(objects).toHaveLength(1001);
    expect(objects.at(-1)?.Key).toBe('full/last/full.dump');
    const inputs = mockSend.mock.calls.map(([command]) => {
      expect(command).toBeInstanceOf(ListObjectsV2Command);
      return (command as ListObjectsV2Command).input;
    });
    expect(inputs).toEqual([
      expect.objectContaining({
        Prefix: 'full/',
        ContinuationToken: undefined,
      }),
      expect.objectContaining({
        Prefix: 'full/',
        ContinuationToken: 'synthetic-page-2',
      }),
    ]);
  });

  it.each([undefined, 'repeated-token'])(
    'rejects incomplete/cyclic pagination %j',
    async (next) => {
      mockSend.mockResolvedValue({
        Contents: [],
        IsTruncated: true,
        NextContinuationToken: next,
      });
      await expect(service.list('logs/')).rejects.toThrow(
        'R2_LIST_PAGINATION_FAILED',
      );
      expect(mockSend).toHaveBeenCalledTimes(next ? 2 : 1);
    },
  );
});
