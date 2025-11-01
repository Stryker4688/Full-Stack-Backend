// backend/src/controllers/adminController.ts - به‌روزرسانی شده
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import User from '../../models/users';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { clearUserCache } from '../../utils/cacheUtils';

export const createAdmin = async (req: AuthRequest, res: Response) => {
    try {
        const { name, email, password } = req.body;

        logger.info('Creating new admin', {
            superAdminId: req.userId,
            adminEmail: email
        });

        // بررسی وجود کاربر
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(400).json({ message: 'کاربر با این ایمیل وجود دارد' });
            return;
        }

        // هش کردن رمز عبور
        const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
            .update(password)
            .digest('hex');
        const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

        // ایجاد ادمین
        const admin = new User({
            name,
            email,
            password: hashedPassword,
            role: 'admin',
            emailVerified: true // ادمین‌ها نیاز به تأیید ایمیل ندارند
        });

        await admin.save();

        LoggerService.userLog(req.userId!, 'create_admin', {
            adminId: admin._id.toString(),
            email: admin.email
        });

        logger.info('Admin created successfully', {
            superAdminId: req.userId,
            adminId: admin._id.toString()
        });

        res.status(201).json({
            message: 'ادمین با موفقیت ایجاد شد',
            admin: {
                id: admin._id.toString(),
                name: admin.name,
                email: admin.email,
                role: admin.role,
                isActive: admin.isActive,
                createdAt: admin.createdAt
            }
        });

    } catch (error) {
        LoggerService.errorLog('createAdmin', error, {
            superAdminId: req.userId,
            adminData: req.body
        });
        res.status(500).json({ message: 'خطا در ایجاد ادمین', error });
    }
};

export const getAdmins = async (req: AuthRequest, res: Response) => {
    try {
        const { page = 1, limit = 10 } = req.query;

        // فقط ادمین‌ها را برگردان (نه سوپر ادمین‌ها)
        const admins = await User.find({
            role: 'admin'
        })
            .select('-password')
            .sort({ createdAt: -1 })
            .limit(Number(limit))
            .skip((Number(page) - 1) * Number(limit));

        const total = await User.countDocuments({
            role: 'admin'
        });

        const result = {
            admins,
            totalPages: Math.ceil(total / Number(limit)),
            currentPage: Number(page),
            total
        };

        logger.debug('Admins list fetched', {
            superAdminId: req.userId,
            count: admins.length
        });

        res.json(result);

    } catch (error) {
        LoggerService.errorLog('getAdmins', error, {
            superAdminId: req.userId
        });
        res.status(500).json({ message: 'خطا در دریافت لیست ادمین‌ها', error });
    }
};

export const deleteAdmin = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        // جلوگیری از حذف خود سوپر ادمین
        if (id === req.userId) {
            res.status(400).json({ message: 'نمی‌توانید خودتان را حذف کنید' });
            return;
        }

        const admin = await User.findOneAndDelete({
            _id: id,
            role: 'admin' // فقط ادمین معمولی قابل حذف است
        });

        if (!admin) {
            res.status(404).json({ message: 'ادمین یافت نشد' });
            return;
        }

        await clearUserCache(id);

        LoggerService.userLog(req.userId!, 'delete_admin', {
            adminId: id,
            adminEmail: admin.email
        });

        logger.info('Admin deleted successfully', {
            superAdminId: req.userId,
            adminId: id
        });

        res.json({ message: 'ادمین با موفقیت حذف شد' });

    } catch (error) {
        LoggerService.errorLog('deleteAdmin', error, {
            superAdminId: req.userId,
            adminId: req.params.id
        });
        res.status(500).json({ message: 'خطا در حذف ادمین', error });
    }
};

export const toggleAdminStatus = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        const admin = await User.findOne({
            _id: id,
            role: 'admin' // فقط ادمین معمولی
        });

        if (!admin) {
            res.status(404).json({ message: 'ادمین یافت نشد' });
            return;
        }

        admin.isActive = !admin.isActive;
        await admin.save();

        await clearUserCache(id);

        LoggerService.userLog(req.userId!, 'toggle_admin_status', {
            adminId: id,
            newStatus: admin.isActive ? 'active' : 'inactive'
        });

        logger.info('Admin status toggled', {
            superAdminId: req.userId,
            adminId: id,
            isActive: admin.isActive
        });

        res.json({
            message: `ادمین ${admin.isActive ? 'فعال' : 'غیرفعال'} شد`,
            admin: {
                id: admin._id.toString(),
                name: admin.name,
                email: admin.email,
                isActive: admin.isActive
            }
        });

    } catch (error) {
        LoggerService.errorLog('toggleAdminStatus', error, {
            superAdminId: req.userId,
            adminId: req.params.id
        });
        res.status(500).json({ message: 'خطا در تغییر وضعیت ادمین', error });
    }
};