// backend/src/middlewares/auth.ts - Optimized with Redis
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { cacheWithFallback, generateKey, CACHE_TTL } from '../utils/cacheUtils';
import User from '../models/users';
import { logger } from '../config/logger';

export interface AuthRequest extends Request {
    userId?: string;
    user?: any;
    impersonatedBy?: string;
}

export const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;

        // Get user data with cache
        const user = await cacheWithFallback(
            generateKey.userProfile(decoded.userId),
            async () => await User.findById(decoded.userId).select('-password'),
            CACHE_TTL.USER_PROFILE
        );

        if (!user) {
            return res.status(403).json({
                success: false,
                message: 'User not found'
            });
        }

        if (!user.isActive) {
            return res.status(403).json({
                success: false,
                message: 'User account is deactivated'
            });
        }

        // Set user data in request
        req.userId = decoded.userId;
        req.user = {
            userId: decoded.userId,
            impersonatedBy: decoded.impersonatedBy,
            originalRole: decoded.originalRole,
            role: user.role,
            email: user.email,
            emailVerified: user.emailVerified
        };

        logger.debug('Token authentication successful', {
            userId: decoded.userId,
            role: user.role
        });

        next();
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(403).json({
                success: false,
                message: 'Token expired'
            });
        }

        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(403).json({
                success: false,
                message: 'Invalid token'
            });
        }

        logger.error('Token authentication error', { error });
        return res.status(500).json({
            success: false,
            message: 'Authentication error'
        });
    }
};

// Middleware for requiring email verification
export const requireEmailVerification = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        if (!req.user || !req.user.userId) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        // Get fresh user data to check email verification status
        const user = await cacheWithFallback(
            generateKey.userProfile(req.user.userId),
            async () => await User.findById(req.user.userId).select('emailVerified'),
            CACHE_TTL.SHORT
        );

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (!user.emailVerified) {
            return res.status(403).json({
                success: false,
                message: 'Email verification required',
                email: user.email
            });
        }

        next();
    } catch (error) {
        logger.error('Email verification check error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};