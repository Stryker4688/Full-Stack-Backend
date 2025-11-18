// backend/src/middlewares/errorHandler.ts - Enhanced with Redis
import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';
import { redisClient } from '../config/redis';
import { AuthRequest } from './auth';
import { cacheWithFallback, generateKey, CACHE_TTL } from '../utils/cacheUtils';

// Custom error types for different error scenarios
export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly code?: string;

    constructor(
        message: string,
        statusCode: number = 500,
        isOperational: boolean = true,
        code?: string
    ) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperational;
        this.code = code;

        Error.captureStackTrace(this, this.constructor);
    }
}

// Specific error types for different use cases
export class AuthError extends AppError {
    constructor(message: string = 'Authentication failed', code?: string) {
        super(message, 401, true, code);
    }
}

export class ValidationError extends AppError {
    constructor(message: string = 'Validation failed', code?: string) {
        super(message, 400, true, code);
    }
}

export class ForbiddenError extends AppError {
    constructor(message: string = 'Access forbidden', code?: string) {
        super(message, 403, true, code);
    }
}

export class NotFoundError extends AppError {
    constructor(message: string = 'Resource not found', code?: string) {
        super(message, 404, true, code);
    }
}

export class RateLimitError extends AppError {
    constructor(message: string = 'Too many requests', code?: string) {
        super(message, 429, true, code);
    }
}

export class DatabaseError extends AppError {
    constructor(message: string = 'Database error', code?: string) {
        super(message, 500, true, code);
    }
}

export class RedisError extends AppError {
    constructor(message: string = 'Cache service error', code?: string) {
        super(message, 500, true, code);
    }
}

export class ExternalServiceError extends AppError {
    constructor(message: string = 'External service error', code?: string) {
        super(message, 502, true, code);
    }
}

// Error management with Redis caching
class ErrorManager {
    private static readonly ERROR_TTL = 24 * 60 * 60; // 24 hours
    private static readonly MAX_RECENT_ERRORS = 100;

    // Store error in Redis with enhanced structure
    static async logErrorToRedis(errorData: any): Promise<void> {
        try {
            const errorId = `error:${Date.now()}:${Math.random().toString(36).substr(2, 9)}`;
            const errorKey = generateKey.userProfile(`error:${errorId}`);

            const enhancedErrorData = {
                ...errorData,
                id: errorId,
                timestamp: new Date().toISOString()
            };

            await redisClient.setEx(
                errorKey,
                this.ERROR_TTL,
                JSON.stringify(enhancedErrorData)
            );

            // Add to recent errors list using Sorted Set for sorting
            await redisClient.zAdd('recent_errors', {
                score: Date.now(),
                value: errorKey
            });

            // Keep only recent errors
            await redisClient.zRemRangeByScore('recent_errors', 0, Date.now() - (7 * 24 * 60 * 60 * 1000)); // Remove errors older than 7 days
            await redisClient.zRemRangeByRank('recent_errors', 0, -this.MAX_RECENT_ERRORS - 1); // Keep only latest errors

        } catch (redisError) {
            logger.error('Failed to log error to Redis', { redisError });
        }
    }

    // Get recent errors from Redis
    static async getRecentErrors(limit: number = 50): Promise<any[]> {
        try {
            const errorKeys = await redisClient.zRange('recent_errors', -limit, -1, { REV: true });
            const errors: any[] = [];

            for (const key of errorKeys) {
                const errorData = await redisClient.get(key);
                if (errorData) {
                    errors.push(JSON.parse(errorData));
                }
            }

            return errors;
        } catch (error) {
            logger.error('Failed to get recent errors from Redis', { error });
            return [];
        }
    }

    // Get error statistics with caching
    static async getErrorStats(): Promise<any> {
        const cacheKey = 'error_stats';

        return await cacheWithFallback(
            cacheKey,
            async () => {
                try {
                    const totalErrors = await redisClient.zCard('recent_errors');
                    const lastHour = Date.now() - (60 * 60 * 1000);
                    const recentErrors = await redisClient.zCount('recent_errors', lastHour, Date.now());

                    return {
                        totalErrors,
                        recentErrors,
                        lastUpdated: new Date()
                    };
                } catch (error) {
                    logger.error('Failed to get error stats', { error });
                    return {
                        totalErrors: 0,
                        recentErrors: 0,
                        lastUpdated: new Date()
                    };
                }
            },
            CACHE_TTL.SHORT
        );
    }
}

// Main error handling middleware
export const errorHandler = (
    error: Error | AppError,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const authReq = req as AuthRequest;
    const userId = authReq.userId || authReq.user?.userId || 'anonymous';

    const errorData = {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip || 'unknown',
        userId: userId !== 'anonymous' ? userId : undefined,
        statusCode: error instanceof AppError ? error.statusCode : 500,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString()
    };

    // Handle different types of errors
    if (error instanceof AppError) {
        logger.warn('Operational error handled', errorData);

        // Store in Redis (asynchronously)
        ErrorManager.logErrorToRedis(errorData).catch(() => { });

        return res.status(error.statusCode).json({
            success: false,
            message: error.message,
            code: error.code,
            ...(process.env.NODE_ENV === 'development' && {
                stack: error.stack,
                path: req.path
            })
        });
    }

    // JWT specific errors
    if (error.name === 'JsonWebTokenError') {
        logger.warn('JWT error', errorData);
        ErrorManager.logErrorToRedis(errorData).catch(() => { });

        return res.status(401).json({
            success: false,
            message: 'Invalid token',
            code: 'INVALID_TOKEN'
        });
    }

    if (error.name === 'TokenExpiredError') {
        logger.warn('JWT expired', errorData);
        ErrorManager.logErrorToRedis(errorData).catch(() => { });

        return res.status(401).json({
            success: false,
            message: 'Token expired',
            code: 'TOKEN_EXPIRED'
        });
    }

    // MongoDB errors
    if (error.name === 'MongoError' || error.name === 'MongoServerError') {
        logger.error('Database error', errorData);
        ErrorManager.logErrorToRedis(errorData).catch(() => { });

        const message = process.env.NODE_ENV === 'development'
            ? `Database error: ${error.message}`
            : 'Database operation failed';

        return res.status(500).json({
            success: false,
            message,
            code: 'DATABASE_ERROR'
        });
    }

    // System errors (unknown)
    logger.error('Unhandled system error', errorData);
    ErrorManager.logErrorToRedis(errorData).catch(() => { });

    const response: any = {
        success: false,
        message: process.env.NODE_ENV === 'development'
            ? `Server error: ${error.message}`
            : 'Internal server error',
        code: 'INTERNAL_ERROR'
    };

    if (process.env.NODE_ENV === 'development') {
        response.stack = error.stack;
        response.path = req.path;
    }

    res.status(500).json(response);
};

// Middleware for 404 errors
export const notFoundHandler = (req: Request, res: Response, next: NextFunction) => {
    const error = new NotFoundError(`Route not found: ${req.method} ${req.url}`);
    next(error);
};

// Middleware for async errors
export const asyncErrorHandler = (fn: Function) => {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

// Route to get error logs (Admin only)
export const getErrorLogs = async (req: AuthRequest, res: Response) => {
    try {
        const { limit = 50 } = req.query;
        const errors = await ErrorManager.getRecentErrors(Number(limit));
        const stats = await ErrorManager.getErrorStats();

        res.json({
            success: true,
            errors,
            stats
        });
    } catch (error) {
        logger.error('Failed to get error logs', { error });
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve error logs'
        });
    }
};

export { ErrorManager };