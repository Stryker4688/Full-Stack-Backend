// backend/src/middleware/requestLogger.ts
import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';
import { AuthRequest } from './auth';

// Request logging middleware
export const requestLogger = (req: AuthRequest, res: Response, next: NextFunction) => {
    const start = Date.now();

    // Log incoming request - using info instead of http
    logger.info('Incoming Request', {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.userId || 'anonymous'
    });

    // When response is sent
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

// Middleware for error logging
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