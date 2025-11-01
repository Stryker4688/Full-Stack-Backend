// backend/src/middleware/adminAuth.ts - به‌روزرسانی شده
import { Response, NextFunction } from 'express';
import { AuthRequest } from './auth';
import User from '../models/users';

// فقط سوپر ادمین (فقط برای ایجاد/حذف ادمین)
export const requireSuperAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        if (!req.userId) {
            res.status(401).json({ message: 'دسترسی غیرمجاز' });
            return;
        }

        const user = await User.findById(req.userId);
        if (!user || user.role !== 'super_admin') {
            res.status(403).json({ message: 'فقط سوپر ادمین مجاز است' });
            return;
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(500).json({ message: 'خطا در بررسی دسترسی' });
    }
};

// ادمین و سوپر ادمین (برای تمام کارهای دیگر)
export const requireAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        if (!req.userId) {
            res.status(401).json({ message: 'دسترسی غیرمجاز' });
            return;
        }

        const user = await User.findById(req.userId);
        if (!user || (user.role !== 'admin' && user.role !== 'super_admin')) {
            res.status(403).json({ message: 'فقط ادمین‌ها مجاز هستند' });
            return;
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(500).json({ message: 'خطا در بررسی دسترسی' });
    }
};