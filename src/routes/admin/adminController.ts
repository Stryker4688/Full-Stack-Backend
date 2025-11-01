// backend/src/controllers/adminController.ts - بهینه‌سازی شده با Redis
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import User from '../../models/users';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { clearUserCache } from '../../utils/cacheUtils';
import { redisClient } from '../../config/redis';

// کلیدهای کش
const CACHE_KEYS = {
    ADMINS_LIST: 'admins_list',
    ADMIN_DETAIL: 'admin_detail',
    SUPER_ADMINS: 'super_admins'
};

// زمان انقضای کش (ثانیه)
const CACHE_TTL = {
    SHORT: 300,    // 5 دقیقه
    MEDIUM: 1800,  // 30 دقیقه
    LONG: 3600     // 1 ساعت
};

// توابع کمکی کش
const cacheGet = async (key: string): Promise<any> => {
    try {
        const cached = await redisClient.get(key);
        return cached ? JSON.parse(cached) : null;
    } catch (error) {
        logger.error('Cache get error', { key, error });
        return null;
    }
};

const cacheSet = async (key: string, data: any, ttl: number = CACHE_TTL.MEDIUM): Promise<void> => {
    try {
        await redisClient.setEx(key, ttl, JSON.stringify(data));
    } catch (error) {
        logger.error('Cache set error', { key, error });
    }
};

const invalidateAdminCache = async (): Promise<void> => {
    try {
        const listKeys = await redisClient.keys(`${CACHE_KEYS.ADMINS_LIST}:*`);
        const detailKeys = await redisClient.keys(`${CACHE_KEYS.ADMIN_DETAIL}:*`);
        const superAdminKeys = await redisClient.keys(`${CACHE_KEYS.SUPER_ADMINS}:*`);

        const allKeys = [...listKeys, ...detailKeys, ...superAdminKeys];

        if (allKeys.length > 0) {
            await redisClient.del(allKeys);
            logger.debug('Admin cache invalidated', { keysCount: allKeys.length });
        }
    } catch (error) {
        logger.error('Admin cache invalidation error', { error });
    }
};

export const createAdmin = async (req: AuthRequest, res: Response) => {
    try {
        const { name, email, password } = req.body;

        logger.info('Creating new admin', {
            superAdminId: req.userId,
            adminEmail: email
        });

        // بررسی کش برای کاربر موجود
        const userCacheKey = `${CACHE_KEYS.ADMIN_DETAIL}:${email}`;
        const existingUserCached = await cacheGet(userCacheKey);

        if (existingUserCached) {
            res.status(400).json({ message: 'کاربر با این ایمیل وجود دارد' });
            return;
        }

        // بررسی وجود کاربر در دیتابیس
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            // ذخیره در کش
            await cacheSet(userCacheKey, { exists: true }, CACHE_TTL.SHORT);

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
            emailVerified: true
        });

        await admin.save();

        // 🔥 حذف کش مرتبط
        await invalidateAdminCache();

        // 🔥 ذخیره ادمین جدید در کش
        await cacheSet(`${CACHE_KEYS.ADMIN_DETAIL}:${admin._id.toString()}`, {
            id: admin._id.toString(),
            name: admin.name,
            email: admin.email,
            role: admin.role,
            isActive: admin.isActive
        }, CACHE_TTL.MEDIUM);

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
        const cacheKey = `${CACHE_KEYS.ADMINS_LIST}:${page}:${limit}`;

        // بررسی کش
        const cached = await cacheGet(cacheKey);
        if (cached) {
            logger.debug('Serving admins list from cache', { cacheKey });
            return res.json({
                ...cached,
                fromCache: true
            });
        }

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

        // ذخیره در کش
        await cacheSet(cacheKey, result, CACHE_TTL.SHORT);

        logger.debug('Admins list fetched', {
            superAdminId: req.userId,
            count: admins.length
        });

        res.json({
            ...result,
            fromCache: false
        });

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
            role: 'admin'
        });

        if (!admin) {
            res.status(404).json({ message: 'ادمین یافت نشد' });
            return;
        }

        // 🔥 حذف کش‌های مرتبط
        await Promise.all([
            clearUserCache(id),
            invalidateAdminCache(),
            redisClient.del(`${CACHE_KEYS.ADMIN_DETAIL}:${id}`),
            redisClient.del(`${CACHE_KEYS.ADMIN_DETAIL}:${admin.email}`)
        ]);

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
            role: 'admin'
        });

        if (!admin) {
            res.status(404).json({ message: 'ادمین یافت نشد' });
            return;
        }

        admin.isActive = !admin.isActive;
        await admin.save();

        // 🔥 آپدیت کش
        await cacheSet(`${CACHE_KEYS.ADMIN_DETAIL}:${id}`, {
            id: admin._id.toString(),
            name: admin.name,
            email: admin.email,
            role: admin.role,
            isActive: admin.isActive
        }, CACHE_TTL.MEDIUM);

        // 🔥 حذف کش لیست‌ها
        await invalidateAdminCache();

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

// 🆕 تابع برای دریافت سوپر ادمین‌ها از کش
export const getSuperAdmins = async (req: AuthRequest, res: Response) => {
    try {
        const cacheKey = CACHE_KEYS.SUPER_ADMINS;

        // بررسی کش
        const cached = await cacheGet(cacheKey);
        if (cached) {
            return res.json({
                success: true,
                superAdmins: cached,
                fromCache: true
            });
        }

        const superAdmins = await User.find({ role: 'super_admin' })
            .select('name email isActive createdAt lastLogin')
            .sort({ createdAt: -1 });

        // ذخیره در کش
        await cacheSet(cacheKey, superAdmins, CACHE_TTL.LONG);

        res.json({
            success: true,
            superAdmins,
            fromCache: false
        });

    } catch (error) {
        LoggerService.errorLog('getSuperAdmins', error, {
            superAdminId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت سوپر ادمین‌ها'
        });
    }
};

// 🆕 تابع برای دریافت آمار ادمین‌ها
export const getAdminStats = async (req: AuthRequest, res: Response) => {
    try {
        const cacheKey = `${CACHE_KEYS.ADMINS_LIST}:stats`;

        // بررسی کش
        const cached = await cacheGet(cacheKey);
        if (cached) {
            return res.json({
                success: true,
                stats: cached,
                fromCache: true
            });
        }

        const totalAdmins = await User.countDocuments({ role: 'admin' });
        const activeAdmins = await User.countDocuments({ role: 'admin', isActive: true });
        const totalSuperAdmins = await User.countDocuments({ role: 'super_admin' });

        // آمار ادمین‌های جدید در 30 روز گذشته
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const newAdmins = await User.countDocuments({
            role: 'admin',
            createdAt: { $gte: thirtyDaysAgo }
        });

        const stats = {
            totalAdmins,
            activeAdmins,
            inactiveAdmins: totalAdmins - activeAdmins,
            totalSuperAdmins,
            newAdminsLast30Days: newAdmins
        };

        // ذخیره در کش
        await cacheSet(cacheKey, stats, CACHE_TTL.SHORT);

        res.json({
            success: true,
            stats,
            fromCache: false
        });

    } catch (error) {
        LoggerService.errorLog('getAdminStats', error, {
            superAdminId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت آمار ادمین‌ها'
        });
    }
};