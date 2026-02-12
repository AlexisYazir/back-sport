import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { winstonLogger } from './winston.logger';

@Injectable()
export class HttpLoggerMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const start = Date.now();

    res.on('finish', () => {
      const duration = Date.now() - start;

      winstonLogger.info('HTTP Request', {
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        responseTime: `${duration}ms`,
      });
    });

    next();
  }
}
