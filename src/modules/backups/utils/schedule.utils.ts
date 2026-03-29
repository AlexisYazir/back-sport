import { CronJob } from 'cron';

export type UiScheduleType = 'daily' | 'weekly' | 'datetime';
export type DbScheduleMode = 'cron' | 'weekly' | 'datetime';
export const APP_TIME_ZONE = 'America/Mexico_City';

const WEEK_DAYS = [
  'Domingo',
  'Lunes',
  'Martes',
  'Miercoles',
  'Jueves',
  'Viernes',
  'Sabado',
];

export function buildCronFromTime(time: string, dayOfWeek?: number) {
  const [hour, minute] = time.split(':').map(Number);
  if (typeof dayOfWeek === 'number') {
    return `${minute} ${hour} * * ${dayOfWeek}`;
  }
  return `${minute} ${hour} * * *`;
}

export function buildScheduleConfig(input: {
  scheduleType: UiScheduleType;
  time?: string;
  dayOfWeek?: number;
  runAt?: string | Date;
}) {
  if (input.scheduleType === 'datetime') {
    const runDate = new Date(input.runAt as string | Date);
    return {
      modo_programacion: 'datetime' as DbScheduleMode,
      cron_expression: null,
      dia_semana: null,
      hora: null,
      fecha_ejecucion: runDate,
    };
  }

  const time = input.time ?? '03:00';
  if (input.scheduleType === 'weekly') {
    return {
      modo_programacion: 'weekly' as DbScheduleMode,
      cron_expression: buildCronFromTime(time, input.dayOfWeek ?? 0),
      dia_semana: input.dayOfWeek ?? 0,
      hora: `${time}:00`,
      fecha_ejecucion: null,
    };
  }

  return {
    modo_programacion: 'cron' as DbScheduleMode,
    cron_expression: buildCronFromTime(time),
    dia_semana: null,
    hora: `${time}:00`,
    fecha_ejecucion: null,
  };
}

export function getUiScheduleType(mode: DbScheduleMode): UiScheduleType {
  if (mode === 'weekly') return 'weekly';
  if (mode === 'datetime') return 'datetime';
  return 'daily';
}

export function describeSchedule(config: {
  modo_programacion: DbScheduleMode;
  hora?: string | null;
  dia_semana?: number | null;
  fecha_ejecucion?: Date | string | null;
}) {
  if (config.modo_programacion === 'datetime') {
    return `Fecha exacta: ${new Date(config.fecha_ejecucion as Date | string).toLocaleString('es-MX', {
      timeZone: APP_TIME_ZONE,
    })}`;
  }

  const time = normalizeTime(config.hora ?? '');
  if (config.modo_programacion === 'weekly') {
    return `Semanal: ${WEEK_DAYS[config.dia_semana ?? 0]} a las ${time}`;
  }

  return `Diario a las ${time}`;
}

export function normalizeTime(time?: string | null) {
  if (!time) return '--:--';
  return time.slice(0, 5);
}

export function getNextExecutionFromJob(job: CronJob): Date | null {
  try {
    const next = job.nextDate();
    const maybeJsDate = (next as any)?.toJSDate?.();
    if (maybeJsDate instanceof Date) {
      return maybeJsDate;
    }
    if (next instanceof Date) {
      return next;
    }
    return new Date(String(next));
  } catch {
    return null;
  }
}
