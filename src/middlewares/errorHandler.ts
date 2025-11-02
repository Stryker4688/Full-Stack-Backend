// backend/src/middlewares/errorHandler.ts - Completely rewritten
import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';
import { redisClient } from '../config/redis';
import { AuthRequest } from './auth';

// 🎯 Custom Error Classes
export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly code: string;
    public readonly details?: any;

    constructor(
        message: string,
        statusCode: number = 500,
        code: string = 'INTERNAL_ERROR',
        isOperational: boolean = true,
        details?: any
    ) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperational;
        this.code = code;
        this.details = details;

        Error.captureStackTrace(this, this.constructor);
    }
}

export class ValidationError extends AppError {
    constructor(message: string = 'Validation failed', details?: any) {
        super(message, 400, 'VALIDATION_ERROR', true, details);
    }
}

export class AuthenticationError extends AppError {
    constructor(message: string = 'Authentication required', code: string = 'AUTHENTICATION_REQUIRED') {
        super(message, 401, code, true);
    }
}

export class AuthorizationError extends AppError {
    constructor(message: string = 'Insufficient permissions', code: string = 'INSUFFICIENT_PERMISSIONS') {
        super(message, 403, code, true);
    }
}

export class NotFoundError extends AppError {
    constructor(message: string = 'Resource not found', code: string = 'RESOURCE_NOT_FOUND') {
        super(message, 404, code, true);
    }
}

export class RateLimitError extends AppError {
    public readonly retryAfter?: number;

    constructor(message: string, code: string = 'RATE_LIMIT_EXCEEDED', retryAfter?: number) {
        super(message, 429, code, true);
        this.retryAfter = retryAfter;
    }
}

export class DatabaseError extends AppError {
    constructor(message: string = 'Database operation failed', details?: any) {
        super(message, 500, 'DATABASE_ERROR', true, details);
    }
}

export class ExternalServiceError extends AppError {
    constructor(message: string = 'External service error', service?: string) {
        super(message, 502, 'EXTERNAL_SERVICE_ERROR', true, { service });
    }
}

export class CacheError extends AppError {
    constructor(message: string = 'Cache service error') {
        super(message, 500, 'CACHE_SERVICE_ERROR', true);
    }
}

// 🎯 Error Logging and Storage
interface ErrorLog {
    id: string;
    timestamp: Date;
    error: string;
    code: string;
    statusCode: number;
    stack?: string;
    url: string;
    method: string;
    ip: string;
    userId?: string;
    userAgent?: string;
    requestId?: string;
    details?: any;
}

class ErrorManager {
    private static readonly ERROR_RETENTION_DAYS = 7;
    private static readonly MAX_ERRORS_STORED = 1000;

    static async logError(errorLog: ErrorLog): Promise<void> {
        try {
            const errorKey = `error:${errorLog.id}`;
            const errorData = JSON.stringify(errorLog);

            // Store error with expiration
            await redisClient.setEx(
                errorKey,
                this.ERROR_RETENTION_DAYS * 24 * 60 * 60, // Convert days to seconds
                errorData
            );

            // Add to recent errors list (keep only latest errors)
            await redisClient.lPush('recent_errors', errorKey);
            await redisClient.lTrim('recent_errors', 0, this.MAX_ERRORS_STORED - 1);

            // Update error statistics
            await this.updateErrorStats(errorLog);

        } catch (redisError) {
            // Fallback to logger if Redis fails
            logger.error('Failed to log error to Redis', { redisError, originalError: errorLog });
        }
    }

    static async getRecentErrors(limit: number = 50): Promise<ErrorLog[]> {
        try {
            const errorKeys = await redisClient.lRange('recent_errors', 0, limit - 1);
            const errors: ErrorLog[] = [];

            for (const key of errorKeys) {
                const errorData = await redisClient.get(key);
                if (errorData) {
                    errors.push(JSON.parse(errorData));
                }
            }

            return errors;
        } catch (error) {
            logger.error('Failed to retrieve recent errors from Redis', { error });
            return [];
        }
    }

    static async getErrorStats(): Promise<any> {
        try {
            const errorKeys = await redisClient.keys('error:*');
            const stats = {
                totalErrors: errorKeys.length,
                byStatusCode: {} as any,
                byCode: {} as any,
                recent24h: 0
            };

            const twentyFourHoursAgo = Date.now() - (24 * 60 * 60 * 1000);

            for (const key of errorKeys) {
                const errorData = await redisClient.get(key);
                if (errorData) {
                    const error: ErrorLog = JSON.parse(errorData);

                    // Count by status code
                    stats.byStatusCode[error.statusCode] = (stats.byStatusCode[error.statusCode] || 0) + 1;

                    // Count by error code
                    stats.byCode[error.code] = (stats.byCode[error.code] || 0) + 1;

                    // Count recent errors
                    if (new Date(error.timestamp).getTime() > twentyFourHoursAgo) {
                        stats.recent24h++;
                    }
                }
            }

            return stats;
        } catch (error) {
            logger.error('Failed to get error statistics', { error });
            return {};
        }
    }

    private static async updateErrorStats(errorLog: ErrorLog): Promise<void> {
        try {
            const dateKey = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
            const statsKey = `error_stats:${dateKey}`;

            await redisClient.hIncrBy(statsKey, 'total', 1);
            await redisClient.hIncrBy(statsKey, `status_${errorLog.statusCode}`, 1);
            await redisClient.hIncrBy(statsKey, `code_${errorLog.code}`, 1);

            // Set expiration for stats key (30 days)
            await redisClient.expire(statsKey, 30 * 24 * 60 * 60);

        } catch (error) {
            logger.error('Failed to update error statistics', { error });
        }
    }
}

// 🎯 Main Error Handling Middleware
export const errorHandler = (
    error: Error | AppError,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const authReq = req as AuthRequest;
    const requestId = (req as any).requestId || generateErrorId();
    const userId = authReq.userId || authReq.user?.userId || 'anonymous';

    // Create error log entry
    const errorLog: ErrorLog = {
        id: requestId,
        timestamp: new Date(),
        error: error.message,
        code: error instanceof AppError ? error.code : 'UNKNOWN_ERROR',
        statusCode: error instanceof AppError ? error.statusCode : 500,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip || 'unknown',
        userId,
        userAgent: req.get('User-Agent'),
        requestId,
        details: error instanceof AppError ? error.details : undefined
    };

    // Log error based on type and severity
    logErrorByType(error, errorLog);

    // Store error for later analysis (non-blocking)
    ErrorManager.logError(errorLog).catch(() => { });

    // Determine if we should include error details in response
    const isDevelopment = process.env.NODE_ENV === 'development';
    const includeDetails = isDevelopment || errorLog.statusCode < 500;

    // Prepare error response
    const errorResponse: any = {
        success: false,
        message: getClientFriendlyMessage(error),
        code: errorLog.code,
        requestId: isDevelopment ? requestId : undefined
    };

    // Add additional details for client
    if (includeDetails) {
        if (error instanceof AppError && error.details) {
            errorResponse.details = error.details;
        }

        if (error instanceof ValidationError) {
            errorResponse.validationErrors = error.details;
        }

        if (error instanceof RateLimitError && error.retryAfter) {
            errorResponse.retryAfter = error.retryAfter;
        }
    }

    // Add stack trace in development
    if (isDevelopment) {
        errorResponse.stack = error.stack;
        errorResponse.path = req.path;
    }

    // Set appropriate status code
    res.status(errorLog.statusCode).json(errorResponse);
};

// 🎯 404 Not Found Handler
export const notFoundHandler = (req: Request, res: Response, next: NextFunction) => {
    const error = new NotFoundError(`Endpoint not found: ${req.method} ${req.url}`);
    next(error);
};

// 🎯 Async Error Wrapper
export const asyncErrorHandler = (fn: Function) => {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

// 🎯 Unhandled Rejection and Exception Handlers
export const registerUnhandledHandlers = (): void => {
    process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
        logger.error('Unhandled Promise Rejection', {
            reason: reason?.message || reason,
            stack: reason?.stack,
            promise: promise.toString()
        });

        // In production, might want to exit process
        if (process.env.NODE_ENV === 'production') {
            process.exit(1);
        }
    });

    process.on('uncaughtException', (error: Error) => {
        logger.error('Uncaught Exception', {
            error: error.message,
            stack: error.stack
        });

        // Always exit process for uncaught exceptions
        process.exit(1);
    });
};

// 🎯 Helper Functions
const generateErrorId = (): string => {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

const logErrorByType = (error: Error, errorLog: ErrorLog): void => {
    if (errorLog.statusCode >= 500) {
        // Server errors - log as error
        logger.error('Server Error Occurred', errorLog);
    } else if (errorLog.statusCode >= 400) {
        // Client errors - log as warning
        logger.warn('Client Error Occurred', errorLog);
    } else {
        // Other errors - log as info
        logger.info('Application Error Occurred', errorLog);
    }
};

const getClientFriendlyMessage = (error: Error): string => {
    if (error instanceof AppError) {
        return error.message;
    }

    // Generic messages for different error types
    if (error.name === 'JsonWebTokenError') {
        return 'Invalid authentication token';
    }

    if (error.name === 'TokenExpiredError') {
        return 'Authentication token has expired';
    }

    if (error.name === 'MongoError' || error.name === 'MongoServerError') {
        return 'Database operation failed. Please try again.';
    }

    if (error.name === 'ValidationError') {
        return 'Data validation failed';
    }

    // Default message
    return process.env.NODE_ENV === 'development'
        ? error.message
        : 'An unexpected error occurred. Please try again.';
};

// 🎯 Export ErrorManager for administrative use
export { ErrorManager };