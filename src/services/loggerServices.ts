// backend/src/services/loggerServices.ts - Fixed type issue
import { logger } from '../config/logger';
import { cacheWithFallback, generateKey, CACHE_TTL } from '../utils/cacheUtils';

export class LoggerService {

    // Auth-related logging
    static async authLog(userId: string, action: string, metadata: any = {}) {
        const logEntry = {
            timestamp: new Date(),
            userId,
            action,
            type: 'auth',
            ...metadata
        };

        logger.info(`Auth action: ${action}`, logEntry);
    }

    // User-related logging
    static async userLog(userId: string, action: string, metadata: any = {}) {
        const logEntry = {
            timestamp: new Date(),
            userId,
            action,
            type: 'user',
            ...metadata
        };

        logger.info(`User action: ${action}`, logEntry);
    }

    // Admin-related logging
    static async adminLog(adminId: string, action: string, metadata: any = {}) {
        const logEntry = {
            timestamp: new Date(),
            adminId,
            action,
            type: 'admin',
            ...metadata
        };

        logger.info(`Admin action: ${action}`, logEntry);
    }

    // Error logging
    static async errorLog(context: string, error: any, metadata: any = {}) {
        const errorEntry = {
            timestamp: new Date(),
            context,
            error: error.message,
            stack: error.stack,
            type: 'error',
            ...metadata
        };

        logger.error(`Error in ${context}: ${error.message}`, errorEntry);
    }

    // Product-related logging
    static async productLog(userId: string, action: string, productId: string, metadata: any = {}) {
        const logEntry = {
            timestamp: new Date(),
            userId,
            productId,
            action,
            type: 'product',
            ...metadata
        };

        logger.info(`Product action: ${action}`, logEntry);
    }

    // System statistics with caching - simplified
    static async getSystemStats() {
        const cacheKey = 'system_stats';

        return await cacheWithFallback(
            cacheKey,
            async () => {
                // This section would fetch data from database in real implementation
                return {
                    totalUsers: 0,
                    activeUsers: 0,
                    totalProducts: 0,
                    pendingTestimonials: 0,
                    systemUptime: process.uptime(),
                    timestamp: new Date()
                };
            },
            CACHE_TTL.MEDIUM
        );
    }
}