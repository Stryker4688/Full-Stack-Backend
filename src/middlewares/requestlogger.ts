// backend/src/middleware/requestLogger.ts
import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';
import { AuthRequest } from './auth';

export const requestLogger = (req: AuthRequest, res: Response, next: NextFunction) => {
    const start = Date.now();

    // لاگ درخواست ورودی - استفاده از info به جای http
    logger.info('Incoming Request', {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.userId || 'anonymous'
    });

    // هنگامی که پاسخ ارسال شد
    res.on('finish', () => {
        const duration = Date.now() - start;
        const logLevel = res.statusCode >= 400 ? 'warn' : 'info';

        logger.log(logLevel, 'Request Completed', {
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
            userId: req.userId || 'anonymous'
        });
    });

    next();
};

// middleware برای لاگینگ خطاها
export const errorLogger = (error: any, req: Request, res: Response, next: NextFunction) => {
    logger.error('Unhandled Error', {
        error: error.message,
        stack: error.stack,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userId: (req as AuthRequest).userId || 'anonymous'
    });

    next(error);
};