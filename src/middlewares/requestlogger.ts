// backend/src/middlewares/requestLogger.ts - Completely rewritten
import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';
import { AuthRequest } from './auth';

export const requestLogger = (req: AuthRequest, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    const requestId = generateRequestId();

    // Add request ID to the request object for tracking
    (req as any).requestId = requestId;

    // Log incoming request
    logger.info('Incoming HTTP Request', {
        requestId,
        method: req.method,
        url: req.url,
        path: req.path,
        query: req.query,
        ip: getClientIP(req),
        userAgent: req.get('User-Agent'),
        userId: req.userId || 'anonymous',
        contentType: req.get('Content-Type'),
        contentLength: req.get('Content-Length'),
        referer: req.get('Referer')
    });

    // Capture response details when request completes
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const logLevel = getLogLevel(res.statusCode);
        const responseSize = res.get('Content-Length') || 'unknown';

        logger.log(logLevel, 'HTTP Request Completed', {
            requestId,
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            duration: `${duration}ms`,
            responseSize,
            ip: getClientIP(req),
            userId: req.userId || 'anonymous',
            userAgent: req.get('User-Agent')
        });
    });

    // Capture response errors
    res.on('error', (error) => {
        logger.error('HTTP Response Error', {
            requestId,
            method: req.method,
            url: req.url,
            error: error.message,
            stack: error.stack,
            ip: getClientIP(req),
            userId: req.userId || 'anonymous'
        });
    });

    next();
};

export const errorLogger = (error: any, req: Request, res: Response, next: NextFunction) => {
    const requestId = (req as any).requestId || 'unknown';
    const authReq = req as AuthRequest;

    logger.error('Unhandled Request Error', {
        requestId,
        error: error.message,
        stack: error.stack,
        method: req.method,
        url: req.url,
        ip: getClientIP(req),
        userId: authReq.userId || 'anonymous',
        userAgent: req.get('User-Agent'),
        headers: sanitizeHeaders(req.headers),
        body: sanitizeBody(req.body)
    });

    next(error);
};

// Enhanced request logger for API metrics
export const apiMetricsLogger = (req: AuthRequest, res: Response, next: NextFunction) => {
    const startTime = process.hrtime();
    const requestId = generateRequestId();

    (req as any).requestId = requestId;
    (req as any).startTime = startTime;

    // Detailed API metrics logging
    logger.debug('API Request Started', {
        requestId,
        method: req.method,
        endpoint: req.path,
        route: req.route?.path || 'unknown',
        ip: getClientIP(req),
        userId: req.userId || 'anonymous',
        userAgent: req.get('User-Agent')?.substring(0, 100), // Limit length
        queryParams: Object.keys(req.query).length > 0 ? req.query : undefined,
        bodyKeys: req.body ? Object.keys(req.body) : []
    });

    res.on('finish', () => {
        const [seconds, nanoseconds] = process.hrtime(startTime);
        const duration = seconds * 1000 + nanoseconds / 1000000; // Convert to milliseconds
        const responseSize = res.get('Content-Length') || 0;

        logger.info('API Request Completed', {
            requestId,
            method: req.method,
            endpoint: req.path,
            statusCode: res.statusCode,
            duration: `${duration.toFixed(2)}ms`,
            responseSize: `${responseSize} bytes`,
            userId: req.userId || 'anonymous',
            cacheStatus: res.get('X-Cache') || 'MISS',
            rateLimitRemaining: res.get('X-RateLimit-Remaining')
        });

        // Log slow requests
        if (duration > 1000) { // More than 1 second
            logger.warn('Slow API Request Detected', {
                requestId,
                method: req.method,
                endpoint: req.path,
                duration: `${duration.toFixed(2)}ms`,
                threshold: '1000ms'
            });
        }
    });

    next();
};

// Security event logger
export const securityLogger = (req: AuthRequest, res: Response, next: NextFunction) => {
    const suspiciousHeaders = ['x-forwarded-for', 'x-real-ip', 'x-cluster-client-ip'];
    const detectedSuspiciousHeaders = suspiciousHeaders.filter(header => req.headers[header]);

    if (detectedSuspiciousHeaders.length > 0) {
        logger.warn('Suspicious Headers Detected', {
            ip: getClientIP(req),
            headers: detectedSuspiciousHeaders,
            userAgent: req.get('User-Agent'),
            url: req.url
        });
    }

    // Log potential security issues
    const userAgent = req.get('User-Agent') || '';
    const suspiciousPatterns = [
        'sqlmap', 'nikto', 'metasploit', 'burpsuite', 'owasp zap'
    ];

    const detectedPattern = suspiciousPatterns.find(pattern =>
        userAgent.toLowerCase().includes(pattern)
    );

    if (detectedPattern) {
        logger.warn('Potential Security Scanner Detected', {
            ip: getClientIP(req),
            userAgent,
            detectedPattern,
            url: req.url
        });
    }

    next();
};

// Helper functions
const generateRequestId = (): string => {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

const getClientIP = (req: Request): string => {
    return (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
        (req.headers['x-real-ip'] as string) ||
        req.socket.remoteAddress ||
        'unknown';
};

const getLogLevel = (statusCode: number): string => {
    if (statusCode >= 500) return 'error';
    if (statusCode >= 400) return 'warn';
    if (statusCode >= 300) return 'info';
    return 'info';
};

const sanitizeHeaders = (headers: any): any => {
    const sensitiveHeaders = ['authorization', 'cookie', 'x-auth-token'];
    const sanitized = { ...headers };

    sensitiveHeaders.forEach(header => {
        if (sanitized[header]) {
            sanitized[header] = '[REDACTED]';
        }
        if (sanitized[header.toLowerCase()]) {
            sanitized[header.toLowerCase()] = '[REDACTED]';
        }
    });

    return sanitized;
};

const sanitizeBody = (body: any): any => {
    if (!body) return body;

    const sensitiveFields = ['password', 'token', 'secret', 'creditCard', 'ssn'];
    const sanitized = { ...body };

    sensitiveFields.forEach(field => {
        if (sanitized[field]) {
            sanitized[field] = '[REDACTED]';
        }
    });

    return sanitized;
};

// Performance monitoring middleware
export const performanceMonitor = (req: AuthRequest, res: Response, next: NextFunction) => {
    const startMemory = process.memoryUsage();
    const startTime = Date.now();

    res.on('finish', () => {
        const endMemory = process.memoryUsage();
        const duration = Date.now() - startTime;

        const memoryDiff = {
            rss: (endMemory.rss - startMemory.rss) / 1024 / 1024, // MB
            heapTotal: (endMemory.heapTotal - startMemory.heapTotal) / 1024 / 1024,
            heapUsed: (endMemory.heapUsed - startMemory.heapUsed) / 1024 / 1024,
            external: (endMemory.external - startMemory.external) / 1024 / 1024
        };

        // Log performance metrics for slow requests or high memory usage
        if (duration > 500 || memoryDiff.heapUsed > 10) {
            logger.info('Performance Metrics', {
                requestId: (req as any).requestId,
                method: req.method,
                endpoint: req.path,
                duration: `${duration}ms`,
                memoryUsage: {
                    rss: `${endMemory.rss / 1024 / 1024}MB`,
                    heapTotal: `${endMemory.heapTotal / 1024 / 1024}MB`,
                    heapUsed: `${endMemory.heapUsed / 1024 / 1024}MB`
                },
                memoryIncrease: memoryDiff
            });
        }
    });

    next();
};