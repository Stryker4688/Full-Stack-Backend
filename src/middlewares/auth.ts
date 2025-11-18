// backend/src/middlewares/auth.ts - Fixed version
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/users';
import { logger } from '../config/logger';

// Extend Express Request interface to include user data
export interface AuthRequest extends Request {
    userId?: string;
    user?: any;
    impersonatedBy?: string;
}

// Middleware to authenticate JWT tokens
export const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract Bearer token

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    try {
        // Verify JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;

        // Get user data from database - without cache for security
        const user = await User.findById(decoded.userId)
            .select('-password -emailVerificationCode -emailVerificationCodeExpires');

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

        // Set user data in request object for use in subsequent middleware/routes
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
        // Handle specific JWT errors
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

// Middleware to require email verification for specific routes
export const requireEmailVerification = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        if (!req.user || !req.user.userId) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        // Get fresh user data to check email verification status - without cache
        const user = await User.findById(req.user.userId)
            .select('emailVerified isActive');

        if (!user) {
            return res.status(404).json({
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