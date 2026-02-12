import * as winston from 'winston';
import 'winston-daily-rotate-file';

const fileRotateTransport = new winston.transports.DailyRotateFile({
  dirname: 'logs',
  filename: 'application-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  maxFiles: '14d',
  zippedArchive: true,
});

export const winstonLogger = winston.createLogger({
  level: 'info', //info todo
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
  ),
  transports: [new winston.transports.Console(), fileRotateTransport],
});
