// backend/src/services/loggerServices.ts - بهینه‌سازی شده با Redis
import { logger } from '../config/logger';
import { redisClient } from '../config/redis';

// کلیدهای کش برای لاگ‌ها
const CACHE_KEYS = {
    LOG_BUFFER: 'log_buffer',
    ERROR_STATS: 'error_stats',
    USER_ACTIVITY: 'user_activity',
    API_METRICS: 'api_metrics',
    SECURITY_EVENTS: 'security_events'
};

// زمان انقضای کش (ثانیه)
const CACHE_TTL = {
    SHORT: 300,      // 5 دقیقه
    MEDIUM: 1800,    // 30 دقیقه
    LONG: 3600,      // 1 ساعت
    VERY_LONG: 86400 // 24 ساعت
};

// توابع کمکی کش
const cacheGet = async (key: string): Promise<any> => {
    try {
        const cached = await redisClient.get(key);
        return cached ? JSON.parse(cached) : null;
    } catch (error) {
        logger.error('Cache get error', { key, error });
        return null;
    }
};

const cacheSet = async (key: string, data: any, ttl: number = CACHE_TTL.MEDIUM): Promise<void> => {
    try {
        await redisClient.setEx(key, ttl, JSON.stringify(data));
    } catch (error) {
        logger.error('Cache set error', { key, error });
    }
};

const cacheIncr = async (key: string, ttl: number = CACHE_TTL.MEDIUM): Promise<number> => {
    try {
        const result = await redisClient.incr(key);

        // اگر اولین بار است، TTL تنظیم کن
        if (result === 1) {
            await redisClient.expire(key, ttl);
        }

        return result;
    } catch (error) {
        logger.error('Cache increment error', { key, error });
        return 0;
    }
};

// بافر برای لاگ‌های پرتکرار
const logBuffer: Map<string, { count: number; firstOccurred: Date; lastData: any }> = new Map();
const BUFFER_FLUSH_INTERVAL = 60000; // 1 دقیقه
const BUFFER_MAX_SIZE = 1000;

// تابع برای فلاش بافر به Redis
const flushLogBuffer = async (): Promise<void> => {
    if (logBuffer.size === 0) return;

    try {
        const timestamp = new Date().toISOString();
        const bufferKey = `${CACHE_KEYS.LOG_BUFFER}:${timestamp}`;

        const bufferData = Array.from(logBuffer.entries()).map(([key, data]) => ({
            key,
            count: data.count,
            firstOccurred: data.firstOccurred,
            lastData: data.lastData
        }));

        await cacheSet(bufferKey, bufferData, CACHE_TTL.LONG);

        // آپدیت آمار
        for (const [key, data] of logBuffer.entries()) {
            if (key.startsWith('error:')) {
                await cacheIncr(`${CACHE_KEYS.ERROR_STATS}:${key}`, CACHE_TTL.VERY_LONG);
            } else if (key.startsWith('user_activity:')) {
                await cacheIncr(`${CACHE_KEYS.USER_ACTIVITY}:${key}`, CACHE_TTL.LONG);
            } else if (key.startsWith('security:')) {
                await cacheIncr(`${CACHE_KEYS.SECURITY_EVENTS}:${key}`, CACHE_TTL.MEDIUM);
            }
        }

        logBuffer.clear();
        logger.debug('Log buffer flushed to Redis', { entries: bufferData.length });
    } catch (error) {
        logger.error('Error flushing log buffer to Redis', { error });
    }
};

// تنظیم تابع فلاش دوره‌ای
setInterval(flushLogBuffer, BUFFER_FLUSH_INTERVAL);

// تابع برای افزودن به بافر
const addToBuffer = (key: string, data: any): void => {
    if (logBuffer.size >= BUFFER_MAX_SIZE) {
        flushLogBuffer().catch(() => { }); // فلاش فوری اگر بافر پر شد
    }

    const existing = logBuffer.get(key);
    if (existing) {
        existing.count++;
        existing.lastData = data;
    } else {
        logBuffer.set(key, {
            count: 1,
            firstOccurred: new Date(),
            lastData: data
        });
    }
};

export class LoggerService {
    static authLog(userId: string, action: string, metadata?: any) {
        const logKey = `auth:${action}:${userId}`;

        // افزودن به بافر
        addToBuffer(logKey, { userId, action, ...metadata });

        logger.info(`Auth Action: ${action}`, {
            userId,
            action,
            ...metadata
        });

        // آپدیت آمار فعالیت کاربر
        this.updateUserActivityStats(userId, action);
    }

    static taskLog(userId: string, action: string, taskId?: string, metadata?: any) {
        const logKey = `task:${action}:${userId}:${taskId || 'unknown'}`;

        addToBuffer(logKey, { userId, action, taskId, ...metadata });

        logger.info(`Task Action: ${action}`, {
            userId,
            taskId,
            action,
            ...metadata
        });
    }

    static userLog(userId: string, action: string, metadata?: any) {
        const logKey = `user_activity:${action}:${userId}`;

        addToBuffer(logKey, { userId, action, ...metadata });

        logger.info(`User Action: ${action}`, {
            userId,
            action,
            ...metadata
        });

        // آپدیت آمار فعالیت کاربر
        this.updateUserActivityStats(userId, action);
    }

    static notificationLog(userId: string, action: string, metadata?: any) {
        const logKey = `notification:${action}:${userId}`;

        addToBuffer(logKey, { userId, action, ...metadata });

        logger.info(`Notification Action: ${action}`, {
            userId,
            action,
            ...metadata
        });
    }

    static cacheLog(action: string, key: string, metadata?: any) {
        const logKey = `cache:${action}:${key}`;

        addToBuffer(logKey, { action, key, ...metadata });

        logger.debug(`Cache Action: ${action}`, {
            action,
            key,
            ...metadata
        });
    }

    static databaseLog(operation: string, collection: string, metadata?: any) {
        const logKey = `db:${operation}:${collection}`;

        addToBuffer(logKey, { operation, collection, ...metadata });

        logger.debug(`Database Operation: ${operation}`, {
            operation,
            collection,
            ...metadata
        });

        // آپدیت آمار API
        this.updateApiMetrics(operation, collection);
    }

    static securityLog(level: 'low' | 'medium' | 'high', message: string, metadata?: any) {
        const logKey = `security:${level}:${message}`;

        addToBuffer(logKey, { level, message, ...metadata });

        const logLevel = level === 'high' ? 'warn' : 'info';
        logger.log(logLevel, `Security: ${message}`, metadata);

        // آپدیت آمار امنیتی
        this.updateSecurityStats(level, message);
    }

    static errorLog(context: string, error: unknown, metadata?: any) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        const stack = error instanceof Error ? error.stack : undefined;

        const logKey = `error:${context}:${errorMessage}`;

        addToBuffer(logKey, { context, error: errorMessage, stack, ...metadata });

        logger.error(`Error in ${context}`, {
            context,
            error: errorMessage,
            stack,
            ...metadata
        });

        // آپدیت آمار خطاها
        this.updateErrorStats(context, errorMessage);
    }

    static searchLog(userId: string, action: string, metadata?: any) {
        const logKey = `search:${action}:${userId}`;

        addToBuffer(logKey, { userId, action, ...metadata });

        logger.info(`Search Action: ${action}`, {
            userId,
            action,
            ...metadata
        });
    }

    // 🆕 متدهای جدید برای مدیریت آمار و متریک‌ها

    private static async updateUserActivityStats(userId: string, action: string): Promise<void> {
        try {
            const date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
            const statsKey = `${CACHE_KEYS.USER_ACTIVITY}:${userId}:${date}`;

            await cacheIncr(`${statsKey}:total`);
            await cacheIncr(`${statsKey}:${action}`);

            // آپدیت آخرین فعالیت
            await cacheSet(`${CACHE_KEYS.USER_ACTIVITY}:${userId}:last_activity`, {
                action,
                timestamp: new Date().toISOString()
            }, CACHE_TTL.MEDIUM);
        } catch (error) {
            logger.error('Error updating user activity stats', { userId, action, error });
        }
    }

    private static async updateApiMetrics(operation: string, collection: string): Promise<void> {
        try {
            const hour = new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH
            const metricsKey = `${CACHE_KEYS.API_METRICS}:${hour}`;

            await cacheIncr(`${metricsKey}:total`);
            await cacheIncr(`${metricsKey}:${operation}`);
            await cacheIncr(`${metricsKey}:${collection}:${operation}`);
        } catch (error) {
            logger.error('Error updating API metrics', { operation, collection, error });
        }
    }

    private static async updateErrorStats(context: string, errorMessage: string): Promise<void> {
        try {
            const date = new Date().toISOString().split('T')[0];
            const errorKey = `${CACHE_KEYS.ERROR_STATS}:${date}`;

            await cacheIncr(`${errorKey}:total`);
            await cacheIncr(`${errorKey}:${context}`);
            await cacheIncr(`${errorKey}:${context}:${errorMessage.substring(0, 50)}`);
        } catch (error) {
            logger.error('Error updating error stats', { context, errorMessage, error });
        }
    }

    private static async updateSecurityStats(level: string, message: string): Promise<void> {
        try {
            const date = new Date().toISOString().split('T')[0];
            const securityKey = `${CACHE_KEYS.SECURITY_EVENTS}:${date}`;

            await cacheIncr(`${securityKey}:total`);
            await cacheIncr(`${securityKey}:${level}`);
            await cacheIncr(`${securityKey}:${level}:${message.substring(0, 50)}`);
        } catch (error) {
            logger.error('Error updating security stats', { level, message, error });
        }
    }

    // 🆕 متدهای عمومی برای دریافت آمار

    static async getUserActivityStats(userId: string, days: number = 7): Promise<any> {
        try {
            const stats: any = {};
            const dates = [];

            for (let i = 0; i < days; i++) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                dates.push(date.toISOString().split('T')[0]);
            }

            for (const date of dates) {
                const key = `${CACHE_KEYS.USER_ACTIVITY}:${userId}:${date}`;
                const total = await cacheGet(`${key}:total`);

                if (total) {
                    stats[date] = {
                        total,
                        // می‌توانید actionهای خاص را هم اینجا اضافه کنید
                    };
                }
            }

            return stats;
        } catch (error) {
            logger.error('Error getting user activity stats', { userId, error });
            return {};
        }
    }

    static async getErrorStats(days: number = 7): Promise<any> {
        try {
            const stats: any = {};
            const dates = [];

            for (let i = 0; i < days; i++) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                dates.push(date.toISOString().split('T')[0]);
            }

            for (const date of dates) {
                const key = `${CACHE_KEYS.ERROR_STATS}:${date}`;
                const total = await cacheGet(`${key}:total`);

                if (total) {
                    stats[date] = { total };
                }
            }

            return stats;
        } catch (error) {
            logger.error('Error getting error stats', { error });
            return {};
        }
    }

    static async getApiMetrics(hours: number = 24): Promise<any> {
        try {
            const metrics: any = {};
            const timeSlots = [];

            for (let i = 0; i < hours; i++) {
                const date = new Date();
                date.setHours(date.getHours() - i);
                timeSlots.push(date.toISOString().slice(0, 13));
            }

            for (const hour of timeSlots) {
                const key = `${CACHE_KEYS.API_METRICS}:${hour}`;
                const total = await cacheGet(`${key}:total`);

                if (total) {
                    metrics[hour] = { total };
                }
            }

            return metrics;
        } catch (error) {
            logger.error('Error getting API metrics', { error });
            return {};
        }
    }

    // 🆕 تابع برای فلاش دستی بافر
    static async flushBuffer(): Promise<void> {
        await flushLogBuffer();
    }

    // 🆕 تابع برای دریافت وضعیت بافر
    static getBufferStatus(): { size: number; entries: Array<{ key: string; count: number }> } {
        const entries = Array.from(logBuffer.entries()).map(([key, data]) => ({
            key,
            count: data.count
        }));

        return {
            size: logBuffer.size,
            entries: entries.slice(0, 10) // فقط 10 entry اول
        };
    }
}

// تابع برای پاکسازی بافر هنگام خاتمه برنامه
process.on('SIGTERM', async () => {
    await flushLogBuffer();
});

process.on('SIGINT', async () => {
    await flushLogBuffer();
});