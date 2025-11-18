// backend/src/middleware/adminAuth.ts - Optimized with Redis
import { Response, NextFunction } from 'express';
import { AuthRequest } from './auth';
import User from '../models/users';
import { logger } from '../config/logger';
import { cacheWithFallback, generateKey, CACHE_TTL } from '../utils/cacheUtils';

// فقط سوپر ادمین (فقط برای ایجاد/حذف ادمین)
export const requireSuperAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        logger.debug('🔍 Checking Super Admin access', { userId: req.userId });

        if (!req.userId) {
            logger.warn('Super Admin check failed - no userId');
            res.status(401).json({ message: 'دسترسی غیرمجاز' });
            return;
        }

        // Check user with cache
        const user = await cacheWithFallback(
            generateKey.userProfile(req.userId),
            async () => await User.findById(req.userId),
            CACHE_TTL.USER_PROFILE
        );

        logger.debug('🔍 Found user for super admin check:', user ? {
            id: user._id,
            email: user.email,
            role: user.role
        } : 'User not found');

        if (!user || user.role !== 'super_admin') {
            logger.warn('Super Admin check failed - invalid role', {
                userId: req.userId,
                userRole: user?.role
            });
            res.status(403).json({ message: 'فقط سوپر ادمین مجاز است' });
            return;
        }

        req.user = user;
        logger.info('Super Admin access granted', { userId: req.userId });
        next();
    } catch (error) {
        logger.error('خطا در بررسی دسترسی سوپر ادمین', { error, userId: req.userId });
        res.status(500).json({ message: 'خطا در بررسی دسترسی' });
    }
};

// ادمین و سوپر ادمین (برای تمام کارهای دیگر)
export const requireAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        logger.debug('🔍 Checking Admin access', { userId: req.userId });

        if (!req.userId) {
            logger.warn('Admin check failed - no userId');
            res.status(401).json({ message: 'دسترسی غیرمجاز' });
            return;
        }

        // Check user with cache
        const user = await cacheWithFallback(
            generateKey.userProfile(req.userId),
            async () => await User.findById(req.userId),
            CACHE_TTL.USER_PROFILE
        );

        logger.debug('🔍 Found user for admin check:', user ? {
            id: user._id,
            email: user.email,
            role: user.role
        } : 'User not found');

        if (!user || (user.role !== 'admin' && user.role !== 'super_admin')) {
            logger.warn('Admin check failed - invalid role', {
                userId: req.userId,
                userRole: user?.role
            });
            res.status(403).json({ message: 'فقط ادمین‌ها مجاز هستند' });
            return;
        }

        req.user = user;
        logger.info('Admin access granted', { userId: req.userId, role: user.role });
        next();
    } catch (error) {
        logger.error('خطا در بررسی دسترسی ادمین', { error, userId: req.userId });
        res.status(500).json({ message: 'خطا در بررسی دسترسی' });
    }
};