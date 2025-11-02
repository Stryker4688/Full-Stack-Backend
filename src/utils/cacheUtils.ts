// backend/src/utils/cacheUtils.ts - Comprehensive Redis utilities
import { redisClient } from '../config/redis';
import { logger } from '../config/logger';

// Cache key constants for consistent naming
export const CACHE_KEYS = {
    // User management
    USER_PROFILE: 'user_profile',
    USER_DETAIL: 'user_detail',
    USER_SESSION: 'user_session',
    USER_STATS: 'user_stats',
    USER_VERIFICATION_STATUS: 'user_verification_status',
    USER_ACTIVITY: 'user_activity',

    // Authentication & security
    LOGIN_ATTEMPTS: 'login_attempts',
    BLOCKED_USERS: 'blocked_users',
    TEMP_TOKENS: 'temp_tokens',
    AUTH_SESSIONS: 'auth_sessions',
    RATE_LIMIT: 'rate_limit',

    // Email verification
    VERIFICATION_CODE: 'verification_code',
    VERIFICATION_ATTEMPTS: 'verification_attempts',
    BLOCKED_VERIFICATION: 'blocked_verification',

    // Password reset
    PASSWORD_RESET_CODE: 'password_reset_code',
    PASSWORD_RESET_ATTEMPTS: 'password_reset_attempts',
    BLOCKED_PASSWORD_RESET: 'blocked_password_reset',
    PASSWORD_RESET_TOKENS: 'password_reset_tokens',

    // Google authentication
    GOOGLE_USER: 'google_user',
    GOOGLE_TOKENS: 'google_tokens',
    GOOGLE_RATE_LIMIT: 'google_rate_limit',

    // Admin management
    ADMINS_LIST: 'admins_list',
    ADMIN_DETAIL: 'admin_detail',
    SUPER_ADMINS: 'super_admins',

    // Product management
    PRODUCTS_LIST: 'products_list',
    PRODUCT_DETAIL: 'product_detail',
    PRODUCT_CATEGORIES: 'product_categories',
    PRODUCT_FEATURED: 'product_featured',

    // Testimonials
    APPROVED_TESTIMONIALS: 'approved_testimonials',
    ALL_TESTIMONIALS: 'all_testimonials',
    TESTIMONIAL_STATS: 'testimonial_stats',
    TESTIMONIAL_DETAIL: 'testimonial_detail',

    // Analytics & logging
    LOG_BUFFER: 'log_buffer',
    ERROR_STATS: 'error_stats',
    API_METRICS: 'api_metrics',
    SECURITY_EVENTS: 'security_events',

    // System
    RECENT_ERRORS: 'recent_errors',
    HEALTH_CHECK: 'health_check'
};

// Cache TTL configurations (seconds)
export const CACHE_TTL = {
    SHORT: 300,        // 5 minutes
    MEDIUM: 1800,      // 30 minutes
    LONG: 3600,        // 1 hour
    VERY_LONG: 86400,  // 24 hours
    EXTREME: 604800    // 7 days
};

// Generic cache operations
export const cacheGet = async (key: string): Promise<any> => {
    try {
        const cached = await redisClient.get(key);
        return cached ? JSON.parse(cached) : null;
    } catch (error) {
        logger.error('Cache get operation failed', { key, error: error instanceof Error ? error.message : 'Unknown error' });
        return null;
    }
};

export const cacheSet = async (key: string, data: any, ttl: number = CACHE_TTL.MEDIUM): Promise<void> => {
    try {
        await redisClient.setEx(key, ttl, JSON.stringify(data));
    } catch (error) {
        logger.error('Cache set operation failed', { key, error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

export const cacheDelete = async (key: string): Promise<void> => {
    try {
        await redisClient.del(key);
    } catch (error) {
        logger.error('Cache delete operation failed', { key, error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

export const cacheIncr = async (key: string, ttl: number = CACHE_TTL.MEDIUM): Promise<number> => {
    try {
        const result = await redisClient.incr(key);
        if (result === 1) {
            await redisClient.expire(key, ttl);
        }
        return result;
    } catch (error) {
        logger.error('Cache increment operation failed', { key, error: error instanceof Error ? error.message : 'Unknown error' });
        return 0;
    }
};

export const cacheExists = async (key: string): Promise<boolean> => {
    try {
        const result = await redisClient.exists(key);
        return result === 1;
    } catch (error) {
        logger.error('Cache exists check failed', { key, error: error instanceof Error ? error.message : 'Unknown error' });
        return false;
    }
};

// Pattern-based cache operations
export const cacheDeletePattern = async (pattern: string): Promise<void> => {
    try {
        const keys = await redisClient.keys(pattern);
        if (keys.length > 0) {
            await redisClient.del(keys);
            logger.debug('Cache keys deleted by pattern', { pattern, count: keys.length });
        }
    } catch (error) {
        logger.error('Cache delete pattern operation failed', { pattern, error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

// User cache management
export const clearUserCache = async (userId: string): Promise<void> => {
    try {
        const patterns = [
            `${CACHE_KEYS.USER_PROFILE}:*${userId}*`,
            `${CACHE_KEYS.USER_DETAIL}:${userId}`,
            `${CACHE_KEYS.USER_SESSION}:${userId}`,
            `${CACHE_KEYS.USER_VERIFICATION_STATUS}:${userId}`,
            `${CACHE_KEYS.TEMP_TOKENS}:${userId}`,
            `${CACHE_KEYS.AUTH_SESSIONS}:${userId}`,
            `${CACHE_KEYS.USER_ACTIVITY}:${userId}:*`
        ];

        await Promise.all(patterns.map(pattern => cacheDeletePattern(pattern)));
        logger.debug('User cache cleared successfully', { userId });
    } catch (error) {
        logger.error('Failed to clear user cache', { userId, error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

export const clearUserCacheByEmail = async (email: string): Promise<void> => {
    try {
        const patterns = [
            `${CACHE_KEYS.USER_PROFILE}:*${email}*`,
            `${CACHE_KEYS.VERIFICATION_CODE}:${email}`,
            `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:${email}:*`,
            `${CACHE_KEYS.BLOCKED_VERIFICATION}:${email}:*`,
            `${CACHE_KEYS.PASSWORD_RESET_CODE}:${email}`,
            `${CACHE_KEYS.PASSWORD_RESET_ATTEMPTS}:${email}:*`,
            `${CACHE_KEYS.BLOCKED_PASSWORD_RESET}:${email}:*`,
            `${CACHE_KEYS.GOOGLE_USER}:email:${email}`
        ];

        await Promise.all(patterns.map(pattern => cacheDeletePattern(pattern)));
        logger.debug('User cache cleared by email', { email });
    } catch (error) {
        logger.error('Failed to clear user cache by email', { email, error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

// Admin cache management
export const clearAdminCache = async (adminId?: string): Promise<void> => {
    try {
        const patterns = [
            `${CACHE_KEYS.ADMINS_LIST}:*`,
            `${CACHE_KEYS.ADMIN_DETAIL}:*`,
            `${CACHE_KEYS.SUPER_ADMINS}:*`
        ];

        if (adminId) {
            patterns.push(`${CACHE_KEYS.ADMIN_DETAIL}:${adminId}`);
        }

        await Promise.all(patterns.map(pattern => cacheDeletePattern(pattern)));
        logger.debug('Admin cache cleared successfully', { adminId });
    } catch (error) {
        logger.error('Failed to clear admin cache', { adminId, error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

// Product cache management
export const clearProductCache = async (productId?: string): Promise<void> => {
    try {
        const patterns = [
            `${CACHE_KEYS.PRODUCTS_LIST}:*`,
            `${CACHE_KEYS.PRODUCT_CATEGORIES}:*`,
            `${CACHE_KEYS.PRODUCT_FEATURED}:*`
        ];

        if (productId) {
            patterns.push(`${CACHE_KEYS.PRODUCT_DETAIL}:${productId}`);
        }

        await Promise.all(patterns.map(pattern => cacheDeletePattern(pattern)));
        logger.debug('Product cache cleared successfully', { productId });
    } catch (error) {
        logger.error('Failed to clear product cache', { productId, error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

// Testimonial cache management
export const clearTestimonialCache = async (): Promise<void> => {
    try {
        const patterns = [
            `${CACHE_KEYS.APPROVED_TESTIMONIALS}:*`,
            `${CACHE_KEYS.ALL_TESTIMONIALS}:*`,
            `${CACHE_KEYS.TESTIMONIAL_STATS}:*`,
            `${CACHE_KEYS.TESTIMONIAL_DETAIL}:*`
        ];

        await Promise.all(patterns.map(pattern => cacheDeletePattern(pattern)));
        logger.debug('Testimonial cache cleared successfully');
    } catch (error) {
        logger.error('Failed to clear testimonial cache', { error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

// Authentication cache management
export const clearAuthCache = async (identifier: string, type: 'email' | 'ip' | 'user' = 'user'): Promise<void> => {
    try {
        let patterns: string[] = [];

        switch (type) {
            case 'email':
                patterns = [
                    `${CACHE_KEYS.LOGIN_ATTEMPTS}:${identifier}:*`,
                    `${CACHE_KEYS.BLOCKED_USERS}:${identifier}:*`,
                    `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:${identifier}:*`,
                    `${CACHE_KEYS.BLOCKED_VERIFICATION}:${identifier}:*`,
                    `${CACHE_KEYS.PASSWORD_RESET_ATTEMPTS}:${identifier}:*`,
                    `${CACHE_KEYS.BLOCKED_PASSWORD_RESET}:${identifier}:*`
                ];
                break;
            case 'ip':
                patterns = [
                    `${CACHE_KEYS.LOGIN_ATTEMPTS}:*:${identifier}`,
                    `${CACHE_KEYS.BLOCKED_USERS}:*:${identifier}`,
                    `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:*:${identifier}`,
                    `${CACHE_KEYS.BLOCKED_VERIFICATION}:*:${identifier}`,
                    `${CACHE_KEYS.PASSWORD_RESET_ATTEMPTS}:*:${identifier}`,
                    `${CACHE_KEYS.BLOCKED_PASSWORD_RESET}:*:${identifier}`,
                    `${CACHE_KEYS.GOOGLE_RATE_LIMIT}:${identifier}`
                ];
                break;
            case 'user':
                patterns = [
                    `${CACHE_KEYS.TEMP_TOKENS}:${identifier}`,
                    `${CACHE_KEYS.AUTH_SESSIONS}:${identifier}`,
                    `${CACHE_KEYS.PASSWORD_RESET_TOKENS}:${identifier}`
                ];
                break;
        }

        await Promise.all(patterns.map(pattern => cacheDeletePattern(pattern)));
        logger.debug('Authentication cache cleared successfully', { identifier, type });
    } catch (error) {
        logger.error('Failed to clear authentication cache', { identifier, type, error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

// Rate limiting utilities
export const checkRateLimit = async (
    identifier: string,
    maxAttempts: number = 10,
    windowMs: number = 300
): Promise<{ allowed: boolean; remaining: number; current: number }> => {
    const rateLimitKey = `${CACHE_KEYS.RATE_LIMIT}:${identifier}`;

    try {
        const current = await cacheIncr(rateLimitKey, windowMs);
        const remaining = Math.max(0, maxAttempts - current);
        const allowed = current <= maxAttempts;

        return { allowed, remaining, current };
    } catch (error) {
        logger.error('Rate limit check failed', { identifier, error: error instanceof Error ? error.message : 'Unknown error' });
        return { allowed: true, remaining: maxAttempts, current: 0 };
    }
};

export const resetRateLimit = async (identifier: string): Promise<void> => {
    try {
        const rateLimitKey = `${CACHE_KEYS.RATE_LIMIT}:${identifier}`;
        await cacheDelete(rateLimitKey);
        logger.debug('Rate limit reset successfully', { identifier });
    } catch (error) {
        logger.error('Failed to reset rate limit', { identifier, error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

// Cache health and maintenance
export const getCacheStats = async (): Promise<{
    totalKeys: number;
    memoryUsage: string;
    connected: boolean;
    info?: any;
}> => {
    try {
        const info = await redisClient.info();
        const keys = await redisClient.dbSize();

        const memoryMatch = info.match(/used_memory_human:(\S+)/);
        const memoryUsage = memoryMatch ? memoryMatch[1] : 'unknown';

        return {
            totalKeys: keys,
            memoryUsage,
            connected: true,
            info
        };
    } catch (error) {
        logger.error('Failed to get cache statistics', { error: error instanceof Error ? error.message : 'Unknown error' });
        return {
            totalKeys: 0,
            memoryUsage: 'unknown',
            connected: false
        };
    }
};

export const flushAllCache = async (): Promise<void> => {
    try {
        await redisClient.flushAll();
        logger.info('All cache flushed successfully');
    } catch (error) {
        logger.error('Failed to flush all cache', { error: error instanceof Error ? error.message : 'Unknown error' });
        throw error;
    }
};

// Cache key generators for consistent naming
export const generateKey = {
    userProfile: (email: string) => `${CACHE_KEYS.USER_PROFILE}:${email}`,
    userDetail: (userId: string) => `${CACHE_KEYS.USER_DETAIL}:${userId}`,
    userSession: (userId: string) => `${CACHE_KEYS.USER_SESSION}:${userId}`,
    userActivity: (userId: string, date: string) => `${CACHE_KEYS.USER_ACTIVITY}:${userId}:${date}`,

    verificationCode: (email: string) => `${CACHE_KEYS.VERIFICATION_CODE}:${email}`,
    passwordResetCode: (email: string) => `${CACHE_KEYS.PASSWORD_RESET_CODE}:${email}`,

    productDetail: (productId: string) => `${CACHE_KEYS.PRODUCT_DETAIL}:${productId}`,
    productsList: (page: number, limit: number, filters: string = '') =>
        `${CACHE_KEYS.PRODUCTS_LIST}:${page}:${limit}:${filters}`,

    testimonialList: (page: number, limit: number, filters: string = '') =>
        `${CACHE_KEYS.APPROVED_TESTIMONIALS}:${page}:${limit}:${filters}`,

    rateLimit: (identifier: string, endpoint: string = '') =>
        `${CACHE_KEYS.RATE_LIMIT}:${endpoint}:${identifier}`,

    adminList: (page: number, limit: number) => `${CACHE_KEYS.ADMINS_LIST}:${page}:${limit}`,

    googleUser: (email: string) => `${CACHE_KEYS.GOOGLE_USER}:email:${email}`,
    googleUserById: (googleId: string) => `${CACHE_KEYS.GOOGLE_USER}:google:${googleId}`
};

// Batch operations for better performance
export const cacheMultiSet = async (keyValuePairs: Array<{ key: string; value: any; ttl?: number }>): Promise<void> => {
    try {
        const multi = redisClient.multi();

        keyValuePairs.forEach(({ key, value, ttl = CACHE_TTL.MEDIUM }) => {
            multi.setEx(key, ttl, JSON.stringify(value));
        });

        await multi.exec();
        logger.debug('Batch cache set operation completed', { count: keyValuePairs.length });
    } catch (error) {
        logger.error('Batch cache set operation failed', { error: error instanceof Error ? error.message : 'Unknown error' });
    }
};

// Cache with fallback pattern
export const cacheWithFallback = async <T>(
    key: string,
    fallback: () => Promise<T>,
    ttl: number = CACHE_TTL.MEDIUM
): Promise<T> => {
    try {
        // Try to get from cache first
        const cached = await cacheGet(key);
        if (cached !== null) {
            return cached;
        }

        // If not in cache, execute fallback
        const data = await fallback();

        // Store in cache for future requests
        await cacheSet(key, data, ttl);

        return data;
    } catch (error) {
        logger.error('Cache with fallback operation failed', { key, error: error instanceof Error ? error.message : 'Unknown error' });
        // If cache fails, still try to get data from fallback
        return await fallback();
    }
};