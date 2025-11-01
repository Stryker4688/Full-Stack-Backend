// backend/src/config/redis.ts
import { createClient } from 'redis';

const redisClient = createClient({
    socket: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379'),
        // اضافه کردن reconnect strategy
        reconnectStrategy: (retries) => {
            if (retries > 10) {
                console.log('❌ Too many reconnection attempts to Redis');
                return new Error('Too many reconnects');
            }
            return Math.min(retries * 100, 3000); // حداکثر 3 ثانیه
        },
        connectTimeout: 10000, // 10 ثانیه timeout برای اتصال
    },
    password: process.env.REDIS_PASSWORD || undefined,
    // اضافه کردن ping interval برای حفظ connection
    pingInterval: 30000 // هر 30 ثانیه
});

// Event handlers بهبود یافته
redisClient.on('error', (err) => {
    console.error('❌ Redis Client Error:', err);
});

redisClient.on('connect', () => {
    console.log('✅ Connected to Redis successfully');
});

redisClient.on('ready', () => {
    console.log('🚀 Redis client is ready');
});

redisClient.on('reconnecting', () => {
    console.log('🔄 Redis is reconnecting...');
});

redisClient.on('end', () => {
    console.log('🔴 Redis connection closed');
});

// متصل کردن به Redis با قابلیت retry
const connectRedis = async (maxRetries = 5): Promise<void> => {
    let retries = 0;

    while (retries < maxRetries) {
        try {
            await redisClient.connect();
            console.log('🎯 Redis connected successfully');
            return;
        } catch (error) {
            retries++;
            console.error(`❌ Redis connection failed (attempt ${retries}/${maxRetries}):`, error);

            if (retries === maxRetries) {
                console.error('💥 Failed to connect to Redis after maximum retries');
                process.exit(1);
            }

            // انتظار قبل از retry بعدی
            await new Promise(resolve => setTimeout(resolve, 2000 * retries));
        }
    }
};

// تابع health check برای Redis
const checkRedisHealth = async (): Promise<boolean> => {
    try {
        await redisClient.ping();
        return true;
    } catch (error) {
        console.error('❌ Redis health check failed:', error);
        return false;
    }
};

// تابع graceful shutdown
const disconnectRedis = async (): Promise<void> => {
    try {
        await redisClient.quit();
        console.log('🔴 Redis disconnected gracefully');
    } catch (error) {
        console.error('❌ Error disconnecting Redis:', error);
    }
};

export {
    redisClient,
    connectRedis,
    checkRedisHealth,
    disconnectRedis
};