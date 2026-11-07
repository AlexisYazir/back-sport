import { CronJob } from 'cron';
import { APP_TIME_ZONE, getNextExecutionFromJob } from './schedule.utils';

describe('Próxima ejecución de respaldos', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  it('convierte la fecha de cron a Date respetando la zona de México', () => {
    jest.useFakeTimers().setSystemTime(new Date('2026-10-31T12:00:00Z'));
    const job = new CronJob(
      '0 3 * * *',
      () => undefined,
      null,
      false,
      APP_TIME_ZONE,
    );

    expect(getNextExecutionFromJob(job)).toEqual(
      new Date('2026-11-01T09:00:00Z'),
    );
    expect(job.isActive).toBe(false);
  });

  it('devuelve null si cron no puede calcular la próxima ejecución', () => {
    const job = new CronJob(
      '0 3 * * *',
      () => undefined,
      null,
      false,
      APP_TIME_ZONE,
    );
    jest.spyOn(job, 'nextDate').mockImplementation(() => {
      throw new Error('No se pudo calcular la fecha');
    });

    expect(getNextExecutionFromJob(job)).toBeNull();
    expect(job.isActive).toBe(false);
  });
});
