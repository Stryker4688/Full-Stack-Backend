// backend/src/middlewares/requireEmailVerification.ts
import { Response, NextFunction } from 'express';
import User from '../models/users';
import { AuthRequest } from './auth';
import logger from '../config/logger';

// Middleware to require email verification for protected routes
export const requireEmailVerification = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction
) => {
    try {
        if (!req.user || !req.user.userId) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        // Fetch user to check email verification status
        const user = await User.findById(req.user.userId);
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
        logger.error('Email verification check error:', error)
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};