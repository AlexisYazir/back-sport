import { ConfigService } from '@nestjs/config';
import { MailService } from './mail.service';

describe('Account deletion notification privacy', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });
  test('the dedicated code template has six digits and does not claim to delete the account', async () => {
    const fetch = jest.fn().mockResolvedValue({ ok: true });
    global.fetch = fetch;
    const mail = new MailService(
      new ConfigService({
        BREVO_API_KEY: 'synthetic-test',
        BREVO_FROM_EMAIL: 'sender@qa.invalid',
      }),
    );
    await mail.sendAccountDeletionCode('owner@qa.invalid', '000007');
    const calls = fetch.mock.calls as unknown as [unknown, { body: string }][];
    const options = calls[0][1];
    const payload = JSON.parse(options.body) as {
      htmlContent: string;
      subject: string;
    };
    expect(payload.subject).toContain('eliminación');
    expect(payload.htmlContent).toContain('<h1>000007</h1>');
    expect(payload.htmlContent).toContain('no elimina tu cuenta por sí solo');
    await expect(
      mail.sendAccountDeletionCode('owner@qa.invalid', '<script>'),
    ).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  test.each(['BREVO_API_KEY', 'RESEND_API_KEY'])(
    'does not consume or surface a provider response containing personal data (%s)',
    async (name) => {
      const text = jest
        .fn()
        .mockResolvedValue('owner@qa.invalid secret-code-000007');
      global.fetch = jest
        .fn()
        .mockResolvedValue({ ok: false, status: 400, text });
      const mail = new MailService(
        new ConfigService({ [name]: 'synthetic-key' }),
      );
      await expect(
        mail.sendAccountDeletionCode('owner@qa.invalid', '000007'),
      ).rejects.toThrow('ACCOUNT_DELETION_DELIVERY_FAILED');
      expect(text).not.toHaveBeenCalled();
    },
  );
});
