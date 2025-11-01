// backend/src/middlewares/errorHandler.ts
import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logger';
import { redisClient } from '../config/redis';
import { AuthRequest } from './auth';

// 🎯 انواع خطاهای سفارشی
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

// خطاهای مخصوص احراز هویت
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

// 🎯 اینترفیس برای خطاهای لاگ شده
interface LoggedError {
    id: string;
    timestamp: Date;
    error: string;
    stack?: string;
    url: string;
    method: string;
    ip: string;
    userId?: string;
    statusCode: number;
    userAgent?: string;
}

// 🎯 کلاس مدیریت خطاها
class ErrorManager {
    private static readonly ERROR_TTL = 24 * 60 * 60; // 24 ساعت

    // ذخیره خطا در Redis
    static async logErrorToRedis(errorData: LoggedError): Promise<void> {
        try {
            const errorKey = `error:${errorData.id}`;
            await redisClient.setEx(
                errorKey,
                this.ERROR_TTL,
                JSON.stringify(errorData)
            );

            // اضافه کردن به لیست خطاهای اخیر
            await redisClient.lPush('recent_errors', errorKey);
            await redisClient.lTrim('recent_errors', 0, 99); // فقط 100 خطای آخر
        } catch (redisError) {
            logger.error('Failed to log error to Redis', { redisError });
            // اگر Redis مشکل داشت، فقط در فایل لاگ کن
        }
    }

    // گرفتن خطاهای اخیر از Redis
    static async getRecentErrors(limit: number = 50): Promise<LoggedError[]> {
        try {
            const errorKeys = await redisClient.lRange('recent_errors', 0, limit - 1);
            const errors: LoggedError[] = [];

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

    // بررسی سلامت Redis
    static async checkRedisHealth(): Promise<boolean> {
        try {
            await redisClient.ping();
            return true;
        } catch {
            return false;
        }
    }
}

// 🎯 تابع اصلی مدیریت خطا
export const errorHandler = (
    error: Error | AppError,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const authReq = req as AuthRequest;
    const userId = authReq.userId || authReq.user?.userId || 'anonymous';

    // ایجاد ID منحصر به فرد برای خطا
    const errorId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    // داده‌های خطا برای ذخیره در Redis
    const errorData: LoggedError = {
        id: errorId,
        timestamp: new Date(),
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip || 'unknown',
        userId: userId !== 'anonymous' ? userId : undefined,
        statusCode: error instanceof AppError ? error.statusCode : 500,
        userAgent: req.get('User-Agent')
    };

    // 🎯 مدیریت انواع مختلف خطاها

    // 1. خطاهای عملیاتی (AppError)
    if (error instanceof AppError) {
        logger.warn('Operational error handled', {
            errorId,
            statusCode: error.statusCode,
            message: error.message,
            code: error.code,
            userId,
            url: req.url
        });

        // ذخیره در Redis (غیرهمزمان - منتظر نمی‌شویم)
        ErrorManager.logErrorToRedis(errorData).catch(() => { });

        return res.status(error.statusCode).json({
            success: false,
            message: error.message,
            code: error.code,
            errorId: process.env.NODE_ENV === 'development' ? errorId : undefined,
            ...(process.env.NODE_ENV === 'development' && {
                stack: error.stack,
                path: req.path
            })
        });
    }

    // 2. خطاهای JWT
    if (error.name === 'JsonWebTokenError') {
        logger.warn('JWT error', { errorId, userId, error: error.message });

        ErrorManager.logErrorToRedis(errorData).catch(() => { });

        return res.status(401).json({
            success: false,
            message: 'Invalid token',
            code: 'INVALID_TOKEN',
            errorId: process.env.NODE_ENV === 'development' ? errorId : undefined
        });
    }

    if (error.name === 'TokenExpiredError') {
        logger.warn('JWT expired', { errorId, userId });

        ErrorManager.logErrorToRedis(errorData).catch(() => { });

        return res.status(401).json({
            success: false,
            message: 'Token expired',
            code: 'TOKEN_EXPIRED',
            errorId: process.env.NODE_ENV === 'development' ? errorId : undefined
        });
    }

    // 3. خطاهای MongoDB
    if (error.name === 'MongoError' || error.name === 'MongoServerError') {
        logger.error('Database error', {
            errorId,
            userId,
            error: error.message,
            name: error.name
        });

        ErrorManager.logErrorToRedis(errorData).catch(() => { });

        // پنهان کردن جزئیات خطای دیتابیس در production
        const message = process.env.NODE_ENV === 'development'
            ? `Database error: ${error.message}`
            : 'Database operation failed';

        return res.status(500).json({
            success: false,
            message,
            code: 'DATABASE_ERROR',
            errorId: process.env.NODE_ENV === 'development' ? errorId : undefined
        });
    }

    // 4. خطاهای Validation (express-validator)
    if (error.name === 'ValidationError' || (error as any).errors) {
        logger.warn('Validation error', { errorId, userId, error: error.message });

        ErrorManager.logErrorToRedis(errorData).catch(() => { });

        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            code: 'VALIDATION_ERROR',
            errors: (error as any).errors,
            errorId: process.env.NODE_ENV === 'development' ? errorId : undefined
        });
    }

    // 5. خطاهای سیستمی (ناشناخته)
    logger.error('Unhandled system error', {
        errorId,
        userId,
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method
    });

    // ذخیره خطاهای سیستمی در Redis
    ErrorManager.logErrorToRedis(errorData).catch(() => { });

    // پاسخ به کاربر
    const response: any = {
        success: false,
        message: process.env.NODE_ENV === 'development'
            ? `Server error: ${error.message}`
            : 'Internal server error',
        code: 'INTERNAL_ERROR',
        errorId: process.env.NODE_ENV === 'development' ? errorId : undefined
    };

    // در حالت development اطلاعات بیشتر
    if (process.env.NODE_ENV === 'development') {
        response.stack = error.stack;
        response.path = req.path;
    }

    res.status(500).json(response);
};

// 🎯 middleware برای خطاهای 404
export const notFoundHandler = (req: Request, res: Response, next: NextFunction) => {
    const error = new NotFoundError(`Route not found: ${req.method} ${req.url}`);
    next(error);
};

// 🎯 middleware برای خطاهای async
export const asyncErrorHandler = (fn: Function) => {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

// 🎯 export کردن ErrorManager برای استفاده در سایر قسمت‌ها
export { ErrorManager };