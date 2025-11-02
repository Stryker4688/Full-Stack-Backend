// backend/src/middlewares/ratelimit.ts - Fixed TypeScript errors
import { NextFunction, Response } from 'express';
import { redisClient } from '../config/redis';
import { AuthRequest } from './auth';
import { logger } from '../config/logger';
import { RateLimitError } from './errorHandler';

interface RateLimitConfig {
    windowMs: number;
    maxRequests: number;
    message: string;
    code: string;
    level: 'low' | 'medium' | 'high';
}

interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    current: number;
    resetTime: number;
    retryAfter?: number;
}

// Comprehensive rate limit configurations
const RATE_LIMIT_CONFIGS: { [key: string]: RateLimitConfig } = {
    // 🔐 Authentication endpoints
    '/auth/login': {
        windowMs: 300, // 5 minutes
        maxRequests: 5,
        message: 'Too many login attempts. Please wait 5 minutes before trying again.',
        code: 'LOGIN_RATE_LIMIT_EXCEEDED',
        level: 'high'
    },
    '/auth/register': {
        windowMs: 900, // 15 minutes
        maxRequests: 3,
        message: 'Too many registration attempts. Please wait 15 minutes before trying again.',
        code: 'REGISTRATION_RATE_LIMIT_EXCEEDED',
        level: 'high'
    },
    '/auth/verify-email': {
        windowMs: 300, // 5 minutes
        maxRequests: 3,
        message: 'Too many email verification attempts. Please wait 5 minutes.',
        code: 'EMAIL_VERIFICATION_LIMIT_EXCEEDED',
        level: 'medium'
    },
    '/auth/resend-verification': {
        windowMs: 600, // 10 minutes
        maxRequests: 2,
        message: 'Too many verification code resend requests. Please wait 10 minutes.',
        code: 'RESEND_VERIFICATION_LIMIT_EXCEEDED',
        level: 'medium'
    },
    '/auth/forgot-password': {
        windowMs: 900, // 15 minutes
        maxRequests: 3,
        message: 'Too many password reset requests. Please wait 15 minutes.',
        code: 'PASSWORD_RESET_LIMIT_EXCEEDED',
        level: 'high'
    },
    '/auth/google': {
        windowMs: 300, // 5 minutes
        maxRequests: 10,
        message: 'Too many Google authentication attempts. Please wait 5 minutes.',
        code: 'GOOGLE_AUTH_LIMIT_EXCEEDED',
        level: 'medium'
    },

    // 📧 Email related endpoints
    '/auth/send-verification': {
        windowMs: 300, // 5 minutes
        maxRequests: 2,
        message: 'Too many email verification requests. Please wait 5 minutes.',
        code: 'SEND_VERIFICATION_LIMIT_EXCEEDED',
        level: 'medium'
    },

    // 👤 User management endpoints
    '/management/users': {
        windowMs: 60, // 1 minute
        maxRequests: 30,
        message: 'Too many user management requests. Please wait 1 minute.',
        code: 'USER_MANAGEMENT_LIMIT_EXCEEDED',
        level: 'medium'
    },

    // 🛍️ Product endpoints
    '/products': {
        windowMs: 60, // 1 minute
        maxRequests: 60,
        message: 'Too many product requests. Please wait 1 minute.',
        code: 'PRODUCT_REQUEST_LIMIT_EXCEEDED',
        level: 'low'
    },
    '/admin/products': {
        windowMs: 60, // 1 minute
        maxRequests: 30,
        message: 'Too many admin product requests. Please wait 1 minute.',
        code: 'ADMIN_PRODUCT_LIMIT_EXCEEDED',
        level: 'medium'
    },

    // 💬 Testimonial endpoints
    '/testimonials': {
        windowMs: 3600, // 1 hour
        maxRequests: 5,
        message: 'Too many testimonial submissions. Please wait 1 hour.',
        code: 'TESTIMONIAL_SUBMISSION_LIMIT_EXCEEDED',
        level: 'medium'
    },

    // 🔍 Search endpoints
    '/home/menu/search': {
        windowMs: 60, // 1 minute
        maxRequests: 30,
        message: 'Too many search requests. Please wait 1 minute.',
        code: 'SEARCH_REQUEST_LIMIT_EXCEEDED',
        level: 'low'
    },

    // Default configuration
    'default': {
        windowMs: 60, // 1 minute
        maxRequests: 100,
        message: 'Too many requests. Please wait 1 minute.',
        code: 'RATE_LIMIT_EXCEEDED',
        level: 'low'
    },

    // Authenticated users get higher limits
    'authenticated': {
        windowMs: 60, // 1 minute
        maxRequests: 200,
        message: 'Too many requests. Please wait 1 minute.',
        code: 'AUTHENTICATED_RATE_LIMIT_EXCEEDED',
        level: 'low'
    }
};

export const rateLimit = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const clientIP = getClientIdentifier(req);
        const path = req.path;
        const method = req.method;
        const isAuthenticated = !!(req.userId || req.user?.userId);

        // Get appropriate rate limit configuration
        const config = getRateLimitConfig(path, method, isAuthenticated);
        const identifier = isAuthenticated ? `user:${req.userId}` : `ip:${clientIP}`;

        // Create unique key for this rate limit bucket
        const rateLimitKey = `rate_limit:${config.level}:${identifier}:${method}:${path}`;

        // Check rate limit using Redis
        const rateLimitResult = await checkRateLimit(rateLimitKey, config);

        // Set rate limit headers
        setRateLimitHeaders(res, rateLimitResult, config);

        if (!rateLimitResult.allowed) {
            logger.warn('Rate limit exceeded', {
                identifier,
                path,
                method,
                current: rateLimitResult.current,
                limit: config.maxRequests,
                level: config.level,
                userAgent: req.get('User-Agent'),
                retryAfter: rateLimitResult.retryAfter
            });

            throw new RateLimitError(config.message, config.code, rateLimitResult.retryAfter);
        }

        // Log approaching rate limits for monitoring
        if (rateLimitResult.remaining <= 3) {
            logger.debug('Rate limit approaching threshold', {
                identifier,
                path,
                remaining: rateLimitResult.remaining,
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
            path: req.path,
            method: req.method
        });

        // Fail open - allow request to proceed if rate limit service is down
        next();
    }
};

export const strictRateLimit = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const clientIP = getClientIdentifier(req);
        const identifier = req.userId ? `user:${req.userId}` : `ip:${clientIP}`;
        const path = req.path;

        const strictConfig: RateLimitConfig = {
            windowMs: 600, // 10 minutes
            maxRequests: 2,
            message: 'For security reasons, this action has been temporarily restricted. Please wait 10 minutes.',
            code: 'STRICT_RATE_LIMIT_EXCEEDED',
            level: 'high'
        };

        const rateLimitKey = `rate_limit:strict:${identifier}:${path}`;
        const rateLimitResult = await checkRateLimit(rateLimitKey, strictConfig);

        setRateLimitHeaders(res, rateLimitResult, strictConfig);

        if (!rateLimitResult.allowed) {
            logger.warn('Strict rate limit exceeded', {
                identifier,
                path,
                current: rateLimitResult.current,
                limit: strictConfig.maxRequests,
                userAgent: req.get('User-Agent')
            });

            throw new RateLimitError(strictConfig.message, strictConfig.code, rateLimitResult.retryAfter);
        }

        next();
    } catch (error) {
        if (error instanceof RateLimitError) {
            return next(error);
        }

        logger.error('Strict rate limit error', { error });
        next(error);
    }
};

export const aggressiveRateLimit = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const clientIP = getClientIdentifier(req);
        const aggressiveConfig: RateLimitConfig = {
            windowMs: 3600, // 1 hour
            maxRequests: 1,
            message: 'This action can only be performed once per hour for security reasons.',
            code: 'AGGRESSIVE_RATE_LIMIT_EXCEEDED',
            level: 'high'
        };

        const rateLimitKey = `rate_limit:aggressive:ip:${clientIP}:${req.path}`;
        const rateLimitResult = await checkRateLimit(rateLimitKey, aggressiveConfig);

        setRateLimitHeaders(res, rateLimitResult, aggressiveConfig);

        if (!rateLimitResult.allowed) {
            logger.warn('Aggressive rate limit exceeded', {
                ip: clientIP,
                path: req.path,
                current: rateLimitResult.current,
                limit: aggressiveConfig.maxRequests
            });

            throw new RateLimitError(aggressiveConfig.message, aggressiveConfig.code, rateLimitResult.retryAfter);
        }

        next();
    } catch (error) {
        if (error instanceof RateLimitError) {
            return next(error);
        }
        next(error);
    }
};

// Administrative functions
export const getRateLimitStatus = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const clientIP = getClientIdentifier(req);
        const identifier = req.userId ? `user:${req.userId}` : `ip:${clientIP}`;

        const status: any = {
            identifier,
            ip: clientIP,
            userId: req.userId,
            isAuthenticated: !!req.userId
        };

        // Check all rate limit configurations for this identifier
        for (const [configName, config] of Object.entries(RATE_LIMIT_CONFIGS)) {
            if (configName === 'default' || configName === 'authenticated') continue;

            const pattern = `rate_limit:${config.level}:${identifier}:*`;
            const keys = await redisClient.keys(pattern);

            for (const key of keys) {
                const current = Number(await redisClient.get(key)) || 0;
                const ttl = await redisClient.ttl(key);

                if (current > 0) {
                    const endpoint = key.split(':').pop();
                    if (endpoint) { // Add null check to fix TypeScript error
                        status[endpoint] = {
                            current,
                            limit: config.maxRequests,
                            remaining: Math.max(0, config.maxRequests - current),
                            ttl,
                            resetIn: `${ttl} seconds`,
                            level: config.level
                        };
                    }
                }
            }
        }

        res.json({
            success: true,
            rateLimitStatus: status,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Rate limit status check failed', { error });
        next(error);
    }
};

export const resetRateLimit = async (identifier: string, pattern: string = '*'): Promise<boolean> => {
    try {
        const keys = await redisClient.keys(`rate_limit:${pattern}:${identifier}:*`);

        if (keys.length > 0) {
            await redisClient.del(keys);
            logger.info('Rate limits reset successfully', {
                identifier,
                pattern,
                keysCount: keys.length
            });
            return true;
        }

        return false;
    } catch (error) {
        logger.error('Failed to reset rate limits', { identifier, error });
        return false;
    }
};

// Global rate limit statistics
export const getGlobalRateLimitStats = async (): Promise<any> => {
    try {
        const keys = await redisClient.keys('rate_limit:*');
        const stats: any = {
            totalKeys: keys.length,
            levels: {}
        };

        for (const key of keys) {
            const level = key.split(':')[1];
            if (level) { // Add null check to fix TypeScript error
                if (!stats.levels[level]) {
                    stats.levels[level] = { count: 0, totalRequests: 0 };
                }

                stats.levels[level].count++;
                const requests = Number(await redisClient.get(key)) || 0;
                stats.levels[level].totalRequests += requests;
            }
        }

        return stats;
    } catch (error) {
        logger.error('Failed to get global rate limit stats', { error });
        return {};
    }
};

// Helper functions
const getClientIdentifier = (req: AuthRequest): string => {
    const xForwardedFor = req.headers['x-forwarded-for'];
    const xRealIp = req.headers['x-real-ip'];

    if (typeof xForwardedFor === 'string') {
        return xForwardedFor.split(',')[0]?.trim() || 'unknown';
    }

    if (typeof xRealIp === 'string') {
        return xRealIp;
    }

    return req.ip || req.socket.remoteAddress || 'unknown';
};

const getRateLimitConfig = (path: string, method: string, isAuthenticated: boolean): RateLimitConfig => {
    // Find specific configuration for this endpoint
    for (const [configPath, config] of Object.entries(RATE_LIMIT_CONFIGS)) {
        if (configPath !== 'default' && configPath !== 'authenticated' && path.includes(configPath)) {
            return config;
        }
    }

    // Return authenticated user config or default
    return isAuthenticated ? RATE_LIMIT_CONFIGS.authenticated : RATE_LIMIT_CONFIGS.default;
};

const checkRateLimit = async (key: string, config: RateLimitConfig): Promise<RateLimitResult> => {
    const multi = redisClient.multi();

    // Increment counter and get TTL in single transaction
    multi.incr(key);
    multi.ttl(key);

    const results = await multi.exec();

    if (!results || results.length < 2) {
        throw new Error('Redis transaction failed');
    }

    const current = Number(results[0]);
    const ttl = Number(results[1]);

    // Set expiration if this is the first request or key has no TTL
    if (current === 1 || ttl <= 0) {
        await redisClient.expire(key, config.windowMs);
    }

    const remaining = Math.max(0, config.maxRequests - current);
    const resetTime = Math.floor(Date.now() / 1000) + (ttl > 0 ? ttl : config.windowMs);
    const allowed = current <= config.maxRequests;
    const retryAfter = allowed ? undefined : (ttl > 0 ? ttl : config.windowMs);

    return {
        allowed,
        remaining,
        current,
        resetTime,
        retryAfter
    };
};

const setRateLimitHeaders = (res: Response, result: RateLimitResult, config: RateLimitConfig): void => {
    res.setHeader('X-RateLimit-Limit', config.maxRequests.toString());
    res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
    res.setHeader('X-RateLimit-Reset', result.resetTime.toString());

    if (result.retryAfter) {
        res.setHeader('Retry-After', result.retryAfter.toString());
    }
};