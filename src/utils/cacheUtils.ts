// backend/src/utils/cacheUtils.ts
import { redisClient } from '../config/redis';
import { logger } from '../config/logger';


export const clearUserCache = async (userId: string): Promise<void> => {
    try {
        const userKey = `user:profile:${userId}`;
        await redisClient.del(userKey);
        console.log(`🧹 Cleared user cache for ${userId}`);
    } catch (error) {
        logger.error('Error clearing user cache:', error);
    }
};