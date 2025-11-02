// backend/src/middlewares/adminAuth.ts - Updated
import { Response, NextFunction } from 'express';
import { AuthRequest } from './auth';
import User from '../models/users';

// Only super admin (only for creating/deleting admin)
export const requireSuperAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        if (!req.userId) {
            res.status(401).json({ message: 'Unauthorized access' });
            return;
        }

        const user = await User.findById(req.userId);
        if (!user || user.role !== 'super_admin') {
            res.status(403).json({ message: 'Only super admin is authorized' });
            return;
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(500).json({ message: 'Error checking access permissions' });
    }
};

// Admin and super admin (for all other tasks)
export const requireAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        if (!req.userId) {
            res.status(401).json({ message: 'Unauthorized access' });
            return;
        }

        const user = await User.findById(req.userId);
        if (!user || (user.role !== 'admin' && user.role !== 'super_admin')) {
            res.status(403).json({ message: 'Only administrators are authorized' });
            return;
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(500).json({ message: 'Error checking access permissions' });
    }
};