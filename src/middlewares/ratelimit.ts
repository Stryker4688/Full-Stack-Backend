// backend/src/middlewares/ratelimit.ts
import { NextFunction, Response } from 'express';
import { redisClient } from '../config/redis';
import { AuthRequest } from './auth';
import { logger } from '../config/logger';
import { RateLimitError } from './errorHandler';

// 🎯 اینترفیس برای تنظیمات Rate Limit
interface RateLimitConfig {
    windowMs: number;
    maxRequests: number;
    message: string;
    code?: string;
}

// 🎯 پیکربندی پیش‌فرض برای endpointهای مختلف
const RATE_LIMIT_CONFIGS: { [key: string]: RateLimitConfig } = {
    // 🔐 Authentication endpoints
    '/auth/login': {
        windowMs: 60, // 1 دقیقه
        maxRequests: 5,
        message: 'تعداد تلاش‌های ورود بیش از حد مجاز است. لطفاً 1 دقیقه صبر کنید.',
        code: 'LOGIN_RATE_LIMIT'
    },
    '/auth/register': {
        windowMs: 60, // 1 دقیقه
        maxRequests: 3,
        message: 'تعداد ثبت‌نام‌ها بیش از حد مجاز است. لطفاً 1 دقیقه صبر کنید.',
        code: 'REGISTER_RATE_LIMIT'
    },
    '/auth/verify-email': {
        windowMs: 300, // 5 دقیقه
        maxRequests: 3,
        message: 'تعداد درخواست‌های تأیید ایمیل بیش از حد مجاز است. لطفاً 5 دقیقه صبر کنید.',
        code: 'EMAIL_VERIFICATION_LIMIT'
    },
    '/auth/resend-verification': {
        windowMs: 300, // 5 دقیقه
        maxRequests: 2,
        message: 'تعداد درخواست‌های ارسال مجدد کد بیش از حد مجاز است. لطفاً 5 دقیقه صبر کنید.',
        code: 'RESEND_VERIFICATION_LIMIT'
    },
    '/auth/google': {
        windowMs: 60, // 1 دقیقه
        maxRequests: 5,
        message: 'تعداد درخواست‌های ورود با گوگل بیش از حد مجاز است.',
        code: 'GOOGLE_AUTH_LIMIT'
    },

    // 🔒 عمومی
    'default': {
        windowMs: 60, // 1 دقیقه
        maxRequests: 10,
        message: 'تعداد درخواست‌ها بیش از حد مجاز است. لطفاً 1 دقیقه صبر کنید.',
        code: 'RATE_LIMIT_EXCEEDED'
    },

    // 👤 کاربران لاگین کرده
    'authenticated': {
        windowMs: 60, // 1 دقیقه
        maxRequests: 30,
        message: 'تعداد درخواست‌ها بیش از حد مجاز است. لطفاً 1 دقیقه صبر کنید.',
        code: 'AUTHENTICATED_RATE_LIMIT'
    }
};

// 🎯 تابع کمکی برای تبدیل به number ایمن
const safeNumber = (value: any): number => {
    if (typeof value === 'number') return value;
    if (typeof value === 'string') return parseInt(value, 10) || 0;
    return 0;
};

// 🎯 تابع اصلی Rate Limit
export const rateLimit = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';

        if (!ip || ip === 'unknown') {
            logger.warn('Rate limit blocked - no valid IP address', {
                ip: req.ip,
                forwarded: req.headers['x-forwarded-for'],
                connection: req.connection.remoteAddress
            });
            throw new RateLimitError('آی‌پی آدرس معتبر یافت نشد.');
        }

        // تشخیص نوع Rate Limit بر اساس مسیر و وضعیت کاربر
        const path = req.path;
        const isAuthenticated = !!(req.userId || req.user?.userId);

        let configKey = 'default';

        // پیدا کردن پیکربندی مناسب
        for (const [key, config] of Object.entries(RATE_LIMIT_CONFIGS)) {
            if (path.includes(key) && key !== 'default' && key !== 'authenticated') {
                configKey = key;
                break;
            }
        }

        // اگر کاربر لاگین کرده است، از limit بالاتر استفاده کن
        if (isAuthenticated && configKey === 'default') {
            configKey = 'authenticated';
        }

        const config = RATE_LIMIT_CONFIGS[configKey];
        const identifier = isAuthenticated ? `user:${req.userId}` : `ip:${ip}`;
        const key = `rate_limit:${configKey}:${identifier}:${path.replace(/\//g, ':')}`;

        // 🎯 استفاده از MULTI/EXEC برای atomic operations
        const multi = redisClient.multi();

        // افزایش شمارنده
        multi.incr(key);

        // تنظیم expire اگر اولین درخواست است
        multi.ttl(key);

        const results = await multi.exec();

        if (!results || results.length < 2) {
            logger.error('Redis pipeline execution failed', { key });
            return next(); // Fail open
        }

        // 🎯 تبدیل ایمن به number
        const current = safeNumber(results[0]);
        const ttl = safeNumber(results[1]);

        // اگر اولین درخواست است یا TTL منفی است، expire تنظیم کن
        if (current === 1 || ttl <= 0) {
            await redisClient.expire(key, config.windowMs);
        }

        // 🎯 محاسبه مقادیر باقیمانده
        const remaining = Math.max(0, config.maxRequests - current);
        const resetTime = Math.floor(Date.now() / 1000) + (ttl > 0 ? ttl : config.windowMs);

        // اضافه کردن headers به response
        res.setHeader('X-RateLimit-Limit', config.maxRequests.toString());
        res.setHeader('X-RateLimit-Remaining', remaining.toString());
        res.setHeader('X-RateLimit-Reset', resetTime.toString());

        // 🎯 بررسی превы limit
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

        // 🎯 لاگ برای درخواست‌های نزدیک به limit
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

        // اگر Redis مشکل داشت، اجازه بده درخواست پردازش بشه
        next();
    }
};

// 🎯 Rate Limit مخصوص برای endpoints بسیار حساس
export const strictRateLimit = async (req: AuthRequest, res: Response, next: NextFunction) => {
    const strictConfig: RateLimitConfig = {
        windowMs: 300, // 5 دقیقه
        maxRequests: 2,
        message: 'برای امنیت حساب کاربری، این عمل به طور موقت محدود شده است. لطفاً 5 دقیقه دیگر تلاش کنید.',
        code: 'STRICT_RATE_LIMIT'
    };

    try {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const identifier = req.userId ? `user:${req.userId}` : `ip:${ip}`;
        const key = `rate_limit:strict:${identifier}:${req.path.replace(/\//g, ':')}`;

        // استفاده از pipeline برای عملکرد بهتر
        const current = await redisClient.incr(key);
        const ttl = await redisClient.ttl(key);

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

// 🎯 تابع برای ریست کردن Rate Limit (برای تست و مدیریت)
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

// 🎯 middleware برای بررسی وضعیت Rate Limit
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

        // بررسی تمام configهای موجود
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