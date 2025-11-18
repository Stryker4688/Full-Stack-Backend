// backend/src/middlewares/ratelimit.ts - Optimized with Redis Pipeline
import { NextFunction, Response } from 'express';
import { redisClient } from '../config/redis';
import { AuthRequest } from './auth';
import { logger } from '../config/logger';
import { RateLimitError } from './errorHandler';

// Rate limit configuration interface
interface RateLimitConfig {
    windowMs: number;
    maxRequests: number;
    message: string;
    code?: string;
}

// Rate limit configurations for different endpoints
const RATE_LIMIT_CONFIGS: { [key: string]: RateLimitConfig } = {
    '/auth/login': {
        windowMs: 60,
        maxRequests: 5,
        message: 'Too many login attempts. Please wait 1 minute.',
        code: 'LOGIN_RATE_LIMIT'
    },
    '/auth/register': {
        windowMs: 60,
        maxRequests: 3,
        message: 'Too many registration attempts. Please wait 1 minute.',
        code: 'REGISTER_RATE_LIMIT'
    },
    '/auth/verify-email': {
        windowMs: 300,
        maxRequests: 3,
        message: 'Too many email verification requests. Please wait 5 minutes.',
        code: 'EMAIL_VERIFICATION_LIMIT'
    },
    '/auth/resend-verification': {
        windowMs: 300,
        maxRequests: 2,
        message: 'Too many resend verification requests. Please wait 5 minutes.',
        code: 'RESEND_VERIFICATION_LIMIT'
    },
    '/auth/google': {
        windowMs: 60,
        maxRequests: 5,
        message: 'Too many Google authentication requests.',
        code: 'GOOGLE_AUTH_LIMIT'
    },
    'default': {
        windowMs: 60,
        maxRequests: 10,
        message: 'Too many requests. Please wait 1 minute.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    'authenticated': {
        windowMs: 60,
        maxRequests: 30,
        message: 'Too many requests. Please wait 1 minute.',
        code: 'AUTHENTICATED_RATE_LIMIT'
    }
};

// Helper function to safely convert values to numbers
const safeNumber = (value: any): number => {
    if (typeof value === 'number') return value;
    if (typeof value === 'string') return parseInt(value, 10) || 0;
    return 0;
};

// Main rate limiting middleware
export const rateLimit = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';

        if (!ip || ip === 'unknown') {
            logger.warn('Rate limit blocked - no valid IP address', {
                ip: req.ip,
                forwarded: req.headers['x-forwarded-for'],
                connection: req.connection.remoteAddress
            });
            throw new RateLimitError('No valid IP address found.');
        }

        const path = req.path;
        const isAuthenticated = !!(req.userId || req.user?.userId);

        let configKey = 'default';

        // Find appropriate rate limit configuration for the current path
        for (const [key, config] of Object.entries(RATE_LIMIT_CONFIGS)) {
            if (path.includes(key) && key !== 'default' && key !== 'authenticated') {
                configKey = key;
                break;
            }
        }

        if (isAuthenticated && configKey === 'default') {
            configKey = 'authenticated';
        }

        const config = RATE_LIMIT_CONFIGS[configKey];
        const identifier = isAuthenticated ? `user:${req.userId}` : `ip:${ip}`;
        const key = `rate_limit:${configKey}:${identifier}:${path.replace(/\//g, ':')}`;

        // Use Redis pipeline for atomic operations
        const multi = redisClient.multi();
        multi.incr(key);
        multi.ttl(key);

        const results = await multi.exec();

        if (!results || results.length < 2) {
            logger.error('Redis pipeline execution failed', { key });
            return next();
        }

        const current = safeNumber(results[0]);
        const ttl = safeNumber(results[1]);

        if (current === 1 || ttl <= 0) {
            await redisClient.expire(key, config.windowMs);
        }

        const remaining = Math.max(0, config.maxRequests - current);
        const resetTime = Math.floor(Date.now() / 1000) + (ttl > 0 ? ttl : config.windowMs);

        // Set rate limit headers for client information
        res.setHeader('X-RateLimit-Limit', config.maxRequests.toString());
        res.setHeader('X-RateLimit-Remaining', remaining.toString());
        res.setHeader('X-RateLimit-Reset', resetTime.toString());

        if (current > config.maxRequests) {
            const retryAfter = ttl > 0 ? ttl : config.windowMs;

            logger.warn('Rate limit exceeded', {
                identifier,
                path,
                current,
                limit: config.maxRequests,
                config: configKey,
                userAgent: req.get('User-Agent'),
                retryAfter
            });

            res.setHeader('Retry-After', retryAfter.toString());
            throw new RateLimitError(config.message, config.code);
        }

        if (remaining <= 2) {
            logger.debug('Rate limit approaching', {
                identifier,
                path,
                current,
                remaining,
                limit: config.maxRequests
            });
        }

        next();
    } catch (error) {
        if (error instanceof RateLimitError) {
            return next(error);
        }

        logger.error('Rate limit middleware error', {
            error: error instanceof Error ? error.message : 'Unknown error',
            ip: req.ip,
            path: req.path
        });

        next();
    }
};

// Strict rate limiting for sensitive operations
export const strictRateLimit = async (req: AuthRequest, res: Response, next: NextFunction) => {
    const strictConfig: RateLimitConfig = {
        windowMs: 300,
        maxRequests: 2,
        message: 'For account security, this action is temporarily limited. Please try again in 5 minutes.',
        code: 'STRICT_RATE_LIMIT'
    };

    try {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const identifier = req.userId ? `user:${req.userId}` : `ip:${ip}`;
        const key = `rate_limit:strict:${identifier}:${req.path.replace(/\//g, ':')}`;

        // Use pipeline for better performance
        const multi = redisClient.multi();
        multi.incr(key);
        multi.ttl(key);

        const results = await multi.exec();

        if (!results || results.length < 2) {
            return next();
        }

        const current = safeNumber(results[0]);
        const ttl = safeNumber(results[1]);

        if (current === 1 || ttl <= 0) {
            await redisClient.expire(key, strictConfig.windowMs);
        }

        const remaining = Math.max(0, strictConfig.maxRequests - current);

        res.setHeader('X-RateLimit-Limit', strictConfig.maxRequests.toString());
        res.setHeader('X-RateLimit-Remaining', remaining.toString());
        res.setHeader('X-RateLimit-Reset', Math.floor(Date.now() / 1000) + (ttl > 0 ? ttl : strictConfig.windowMs));

        if (current > strictConfig.maxRequests) {
            const retryAfter = ttl > 0 ? ttl : strictConfig.windowMs;

            logger.warn('Strict rate limit exceeded', {
                identifier,
                path: req.path,
                current,
                limit: strictConfig.maxRequests
            });

            res.setHeader('Retry-After', retryAfter.toString());
            throw new RateLimitError(strictConfig.message, strictConfig.code);
        }

        next();
    } catch (error) {
        if (error instanceof RateLimitError) {
            return next(error);
        }
        logger.error('Strict rate limit error', { error });
        next();
    }
};

// Reset rate limits for a specific identifier
export const resetRateLimit = async (identifier: string, path: string = ''): Promise<boolean> => {
    try {
        const pattern = path
            ? `rate_limit:*:${identifier}:*${path}*`
            : `rate_limit:*:${identifier}:*`;

        const keys = await redisClient.keys(pattern);

        if (keys.length > 0) {
            await redisClient.del(keys);
            logger.info('Rate limits reset', { identifier, path, keysCount: keys.length });
        }

        return true;
    } catch (error) {
        logger.error('Failed to reset rate limits', { identifier, error });
        return false;
    }
};

// Check current rate limit status
export const rateLimitStatus = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const identifier = req.userId ? `user:${req.userId}` : `ip:${ip}`;
        const path = req.path;

        const status: any = {
            identifier,
            ip,
            userId: req.userId,
            path
        };

        // Check rate limit status for each configuration
        for (const [configKey, config] of Object.entries(RATE_LIMIT_CONFIGS)) {
            if (configKey === 'default' || configKey === 'authenticated') continue;

            const key = `rate_limit:${configKey}:${identifier}:${path.replace(/\//g, ':')}`;
            const current = safeNumber(await redisClient.get(key));
            const ttl = await redisClient.ttl(key);

            if (current > 0) {
                status[configKey] = {
                    current,
                    limit: config.maxRequests,
                    remaining: Math.max(0, config.maxRequests - current),
                    ttl,
                    window: config.windowMs
                };
            }
        }

        res.json({
            success: true,
            rateLimitStatus: status
        });
    } catch (error) {
        logger.error('Rate limit status check failed', { error });
        next(error);
    }
};