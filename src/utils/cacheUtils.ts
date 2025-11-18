// backend/src/utils/cacheUtils.ts - اصلاح نوع بازگشتی
import { redisClient } from '../config/redis';
import { logger } from '../config/logger';

// تابع اصلی شما بدون تغییر
export const clearUserCache = async (userId: string): Promise<void> => {
    try {
        const userKey = `user:profile:${userId}`;
        await redisClient.del(userKey);
        logger.debug(`🧹 Cleared user cache for ${userId}`);
    } catch (error) {
        logger.error('Error clearing user cache:', error);
    }
};

// TTL constants
export const CACHE_TTL = {
    SHORT: 300, // 5 minutes
    MEDIUM: 1800, // 30 minutes
    LONG: 3600, // 1 hour
    VERY_LONG: 86400, // 24 hours
    USER_PROFILE: 7200, // 2 hours
    PRODUCTS: 1800, // 30 minutes
    TESTIMONIALS: 3600 // 1 hour
};

// Cache key generators
export const generateKey = {
    userProfile: (userId: string) => `user:profile:${userId}`,
    testimonialList: (page: number, limit: number, sort: string) =>
        `testimonials:list:${page}:${limit}:${sort}`,
    testimonialStats: () => 'testimonials:stats',
    featuredProducts: (limit: number) => `products:featured:${limit}`,
    menuProducts: (params: string) => `products:menu:${params}`,
    productDetail: (id: string) => `product:detail:${id}`,
    productSearch: (query: string, params: string) => `products:search:${query}:${params}`,
    popularProducts: (limit: number) => `products:popular:${limit}`,
    adminProducts: (params: string) => `products:admin:${params}`,
    userStats: () => 'users:stats',
    userList: (params: string) => `users:list:${params}`,
    adminList: (page: number, limit: number) => `admins:list:${page}:${limit}`
};

// Basic cache operations
export const cacheGet = async (key: string): Promise<any> => {
    try {
        const data = await redisClient.get(key);
        if (data) {
            logger.debug('Cache hit', { key });
            return JSON.parse(data);
        }
        logger.debug('Cache miss', { key });
        return null;
    } catch (error) {
        logger.error('Cache get error', { key, error });
        return null;
    }
};

export const cacheSet = async (key: string, data: any, ttl: number = CACHE_TTL.MEDIUM): Promise<boolean> => {
    try {
        await redisClient.setEx(key, ttl, JSON.stringify(data));
        logger.debug('Cache set successfully', { key, ttl });
        return true;
    } catch (error) {
        logger.error('Cache set error', { key, error });
        return false;
    }
};

export const cacheDelete = async (key: string): Promise<boolean> => {
    try {
        await redisClient.del(key);
        logger.debug('Cache deleted', { key });
        return true;
    } catch (error) {
        logger.error('Cache delete error', { key, error });
        return false;
    }
};

export const cacheDeletePattern = async (pattern: string): Promise<number> => {
    try {
        const keys = await redisClient.keys(pattern);
        if (keys.length > 0) {
            await redisClient.del(keys);
            logger.debug('Cache pattern deleted', { pattern, keysCount: keys.length });
            return keys.length;
        }
        return 0;
    } catch (error) {
        logger.error('Cache pattern delete error', { pattern, error });
        return 0;
    }
};

// Advanced cache operations
export const cacheWithFallback = async <T>(
    key: string,
    fetchData: () => Promise<T>,
    ttl: number = CACHE_TTL.MEDIUM,
    useCache: boolean = true
): Promise<T & { fromCache?: boolean }> => {
    if (!useCache) {
        const freshData = await fetchData();
        return { ...freshData, fromCache: false } as T & { fromCache?: boolean };
    }

    try {
        // Try to get from cache first
        const cached = await cacheGet(key);
        if (cached !== null) {
            return { ...cached, fromCache: true };
        }

        // Fetch fresh data
        const freshData = await fetchData();

        // Cache the fresh data (non-blocking)
        cacheSet(key, freshData, ttl).catch(() => { });

        return { ...freshData, fromCache: false };
    } catch (error) {
        logger.error('Cache with fallback error', { key, error });
        // If cache fails, return fresh data
        const freshData = await fetchData();
        return { ...freshData, fromCache: false };
    }
};

// Cache invalidation functions
export const clearProductCache = async (): Promise<void> => {
    try {
        const deletedCount = await cacheDeletePattern('products:*');
        logger.debug('Product cache cleared', { deletedCount });
    } catch (error) {
        logger.error('Error clearing product cache:', error);
    }
};

export const clearTestimonialCache = async (): Promise<void> => {
    try {
        const deletedCount = await cacheDeletePattern('testimonials:*');
        logger.debug('Testimonial cache cleared', { deletedCount });
    } catch (error) {
        logger.error('Error clearing testimonial cache:', error);
    }
};

export const clearAdminCache = async (): Promise<void> => {
    try {
        const deletedCount = await cacheDeletePattern('admins:*');
        logger.debug('Admin cache cleared', { deletedCount });
    } catch (error) {
        logger.error('Error clearing admin cache:', error);
    }
};

// 🔽 اصلاح نوع بازگشتی این تابع
export const checkCacheHealth = async (): Promise<{ healthy: boolean; latency?: number }> => {
    try {
        const start = Date.now();
        await redisClient.ping();
        const latency = Date.now() - start;
        return { healthy: true, latency };
    } catch (error) {
        logger.error('Cache health check failed', { error });
        return { healthy: false };
    }
};

// Cache statistics
export const getCacheStats = async (): Promise<any> => {
    try {
        const info = await redisClient.info('memory');
        const keys = await redisClient.keys('*');

        return {
            connected: true,
            totalKeys: keys.length,
            memoryInfo: info.split('\n').slice(0, 10)
        };
    } catch (error) {
        logger.error('Get cache stats error', { error });
        return { connected: false };
    }
};