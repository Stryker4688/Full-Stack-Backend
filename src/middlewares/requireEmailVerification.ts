// backend/src/middlewares/requireEmailVerification.ts - Completely rewritten
import { Response, NextFunction } from 'express';
import User from '../models/users';
import { AuthRequest } from './auth';
import { logger } from '../config/logger';
import { cacheGet, generateKey } from '../utils/cacheUtils';

export const requireEmailVerification = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction
) => {
    try {
        if (!req.user || !req.user.userId) {
            logger.warn('Email verification check failed - no user in request', {
                ip: req.ip,
                endpoint: req.path
            });

            return res.status(401).json({
                success: false,
                message: 'Authentication required to access this resource',
                code: 'AUTHENTICATION_REQUIRED'
            });
        }

        const userCacheKey = generateKey.userDetail(req.user.userId);

        // Try to get user from cache first
        let user = await cacheGet(userCacheKey);

        if (!user) {
            // Fetch from database if not in cache
            user = await User.findById(req.user.userId);

            if (!user) {
                logger.warn('Email verification check - user not found', {
                    userId: req.user.userId,
                    ip: req.ip
                });

                return res.status(404).json({
                    success: false,
                    message: 'User account not found',
                    code: 'USER_NOT_FOUND'
                });
            }
        }

        // Check if email is verified
        if (!user.emailVerified) {
            logger.warn('Email verification required for access', {
                userId: req.user.userId,
                email: user.email,
                endpoint: req.path
            });

            return res.status(403).json({
                success: false,
                message: 'Email verification required to access this feature',
                code: 'EMAIL_VERIFICATION_REQUIRED',
                email: user.email,
                redirectTo: '/verify-email'
            });
        }

        // Check if user account is active
        if (!user.isActive) {
            logger.warn('Inactive user attempted to access protected resource', {
                userId: req.user.userId,
                email: user.email
            });

            return res.status(403).json({
                success: false,
                message: 'Your account has been deactivated. Please contact support.',
                code: 'ACCOUNT_DEACTIVATED'
            });
        }

        logger.debug('Email verification check passed', {
            userId: req.user.userId,
            endpoint: req.path
        });

        next();
    } catch (error: any) {
        logger.error('Email verification middleware error', {
            error: error.message,
            userId: req.user?.userId,
            ip: req.ip,
            stack: error.stack
        });

        return res.status(500).json({
            success: false,
            message: 'Server error during access verification',
            code: 'VERIFICATION_SERVICE_ERROR'
        });
    }
};

// Optional: Strict email verification with additional checks
export const requireStrictEmailVerification = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction
) => {
    try {
        if (!req.user || !req.user.userId) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required',
                code: 'STRICT_AUTH_REQUIRED'
            });
        }

        const user = await User.findById(req.user.userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User account not found',
                code: 'USER_NOT_FOUND'
            });
        }

        // Additional strict checks
        if (!user.emailVerified) {
            // Check if verification code is expired
            if (user.emailVerificationCodeExpires && user.emailVerificationCodeExpires < new Date()) {
                logger.warn('Expired verification code detected', {
                    userId: user._id.toString(),
                    email: user.email
                });

                return res.status(403).json({
                    success: false,
                    message: 'Your verification code has expired. Please request a new one.',
                    code: 'VERIFICATION_CODE_EXPIRED',
                    email: user.email
                });
            }

            return res.status(403).json({
                success: false,
                message: 'Email verification is mandatory for this action',
                code: 'STRICT_VERIFICATION_REQUIRED',
                email: user.email
            });
        }

        // Check account status and other security measures
        if (!user.isActive) {
            return res.status(403).json({
                success: false,
                message: 'Account suspended. Please contact administrator.',
                code: 'ACCOUNT_SUSPENDED'
            });
        }

        next();
    } catch (error: any) {
        logger.error('Strict email verification middleware error', {
            error: error.message,
            userId: req.user?.userId
        });

        return res.status(500).json({
            success: false,
            message: 'Security verification service error',
            code: 'SECURITY_VERIFICATION_ERROR'
        });
    }
};

// Middleware to optionally check email verification (doesn't block access)
export const optionalEmailVerification = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction
) => {
    try {
        if (!req.user || !req.user.userId) {
            // No user logged in, proceed without verification check
            return next();
        }

        const userCacheKey = generateKey.userDetail(req.user.userId);
        let user = await cacheGet(userCacheKey);

        if (!user) {
            user = await User.findById(req.user.userId);
        }

        if (user) {
            // Add verification status to request for conditional logic in controllers
            req.user.emailVerified = user.emailVerified;
            req.user.isActive = user.isActive;
        }

        next();
    } catch (error: any) {
        logger.error('Optional email verification check failed', {
            error: error.message,
            userId: req.user?.userId
        });

        // Continue anyway for optional check
        next();
    }
};