// backend/src/config/redis.ts - اصلاح نوع بازگشتی
import { createClient } from 'redis';
import { logger } from './logger';

const redisClient = createClient({
    socket: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379'),
        reconnectStrategy: (retries) => {
            if (retries > 10) {
                console.log('❌ Too many reconnection attempts to Redis');
                return new Error('Too many reconnects');
            }
            return Math.min(retries * 100, 3000);
        },
        connectTimeout: 10000,
    },
    password: process.env.REDIS_PASSWORD || undefined,
    pingInterval: 30000
});

// Event handlers
redisClient.on('error', (err) => {
    logger.error('❌ Redis Client Error:', err);
});

redisClient.on('connect', () => {
    logger.info('✅ Connected to Redis successfully');
});

redisClient.on('ready', () => {
    logger.info('🚀 Redis client is ready');
});

redisClient.on('reconnecting', () => {
    logger.warn('🔄 Redis is reconnecting...');
});

redisClient.on('end', () => {
    logger.warn('🔴 Redis connection closed');
});

const connectRedis = async (maxRetries = 5): Promise<void> => {
    let retries = 0;

    while (retries < maxRetries) {
        try {
            await redisClient.connect();
            logger.info('🎯 Redis connected successfully');
            return;
        } catch (error) {
            retries++;
            logger.error(`❌ Redis connection failed (attempt ${retries}/${maxRetries}):`, error);

            if (retries === maxRetries) {
                logger.error('💥 Failed to connect to Redis after maximum retries');
                process.exit(1);
            }

            await new Promise(resolve => setTimeout(resolve, 2000 * retries));
        }
    }
};

// 🔽 اصلاح نوع بازگشتی این تابع
const checkRedisHealth = async (): Promise<{ healthy: boolean; latency?: number }> => {
    try {
        const start = Date.now();
        await redisClient.ping();
        const latency = Date.now() - start;

        return {
            healthy: true,
            latency
        };
    } catch (error) {
        logger.error('❌ Redis health check failed:', error);
        return { healthy: false };
    }
};

const disconnectRedis = async (): Promise<void> => {
    try {
        await redisClient.quit();
        logger.info('🔴 Redis disconnected gracefully');
    } catch (error) {
        logger.error('❌ Error disconnecting Redis:', error);
    }
};

export {
    redisClient,
    connectRedis,
    checkRedisHealth,
    disconnectRedis
};