// backend/src/middleware/adminAuth.ts - Fixed version
import { Response, NextFunction } from 'express';
import { AuthRequest } from './auth';
import User from '../models/users';
import { logger } from '../config/logger';

// Middleware to require super admin privileges (only for creating/deleting admins)
export const requireSuperAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        logger.debug('🔍 Checking Super Admin access', { userId: req.userId });

        if (!req.userId) {
            logger.warn('Super Admin check failed - no userId');
            return res.status(401).json({
                success: false,
                message: 'Unauthorized access'
            });
        }

        // Check user - without cache for security
        const user = await User.findById(req.userId);

        if (!user || user.role !== 'super_admin') {
            logger.warn('Super Admin check failed - invalid role', {
                userId: req.userId,
                userRole: user?.role
            });
            return res.status(403).json({
                success: false,
                message: 'Only super admin is authorized'
            });
        }

        req.user = user;
        logger.info('Super Admin access granted', { userId: req.userId });
        next();
    } catch (error) {
        logger.error('Error checking super admin access', { error, userId: req.userId });
        res.status(500).json({
            success: false,
            message: 'Error checking access'
        });
    }
};

// Middleware to require admin or super admin privileges (for all other operations)
export const requireAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        logger.debug('🔍 Checking Admin access', { userId: req.userId });

        if (!req.userId) {
            logger.warn('Admin check failed - no userId');
            return res.status(401).json({
                success: false,
                message: 'Unauthorized access'
            });
        }

        // Check user - without cache for security
        const user = await User.findById(req.userId);

        if (!user || (user.role !== 'admin' && user.role !== 'super_admin')) {
            logger.warn('Admin check failed - invalid role', {
                userId: req.userId,
                userRole: user?.role
            });
            return res.status(403).json({
                success: false,
                message: 'Only admins are authorized'
            });
        }

        req.user = user;
        logger.info('Admin access granted', { userId: req.userId, role: user.role });
        next();
    } catch (error) {
        logger.error('Error checking admin access', { error, userId: req.userId });
        res.status(500).json({
            success: false,
            message: 'Error checking access'
        });
    }
};