// backend/src/services/loggerService.ts
import { logger } from '../config/logger';

export class LoggerService {
    static authLog(userId: string, action: string, metadata?: any) {
        logger.info(`Auth Action: ${action}`, {
            userId,
            action,
            ...metadata
        });
    }

    static taskLog(userId: string, action: string, taskId?: string, metadata?: any) {
        logger.info(`Task Action: ${action}`, {
            userId,
            taskId,
            action,
            ...metadata
        });
    }

    static userLog(userId: string, action: string, metadata?: any) {
        logger.info(`User Action: ${action}`, {
            userId,
            action,
            ...metadata
        });
    }

    static notificationLog(userId: string, action: string, metadata?: any) {
        logger.info(`Notification Action: ${action}`, {
            userId,
            action,
            ...metadata
        });
    }

    static cacheLog(action: string, key: string, metadata?: any) {
        logger.debug(`Cache Action: ${action}`, {
            action,
            key,
            ...metadata
        });
    }

    static databaseLog(operation: string, collection: string, metadata?: any) {
        logger.debug(`Database Operation: ${operation}`, {
            operation,
            collection,
            ...metadata
        });
    }

    static securityLog(level: 'low' | 'medium' | 'high', message: string, metadata?: any) {
        const logLevel = level === 'high' ? 'warn' : 'info';
        logger.log(logLevel, `Security: ${message}`, metadata);
    }
    static errorLog(context: string, error: unknown, metadata?: any) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        const stack = error instanceof Error ? error.stack : undefined;

        logger.error(`Error in ${context}`, {
            context,
            error: errorMessage,
            stack,
            ...metadata
        });
    }
    static searchLog(userId: string, action: string, metadata?: any) {
        logger.info(`Search Action: ${action}`, {
            userId,
            action,
            ...metadata
        });
    }
}
