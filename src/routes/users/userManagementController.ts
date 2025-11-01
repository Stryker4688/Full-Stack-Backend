// backend/src/controllers/userManagementController.ts - بهینه‌سازی شده با Redis
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import User from '../../models/users';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import jwt from 'jsonwebtoken';
import { redisClient } from '../../config/redis';

// کلیدهای کش
const CACHE_KEYS = {
    USERS_LIST: 'users_list',
    USER_DETAIL: 'user_detail',
    USER_STATS: 'user_stats',
    USER_SESSION: 'user_session'
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

const invalidateUserCache = async (userId?: string): Promise<void> => {
    try {
        const listKeys = await redisClient.keys(`${CACHE_KEYS.USERS_LIST}:*`);
        const statsKeys = await redisClient.keys(`${CACHE_KEYS.USER_STATS}:*`);

        let allKeys = [...listKeys, ...statsKeys];

        // اگر userId مشخص شده، کش جزئیات کاربر را هم حذف کن
        if (userId) {
            const userDetailKey = `${CACHE_KEYS.USER_DETAIL}:${userId}`;
            allKeys.push(userDetailKey);
        }

        if (allKeys.length > 0) {
            await redisClient.del(allKeys);
            logger.debug('User cache invalidated', {
                keysCount: allKeys.length,
                userId
            });
        }
    } catch (error) {
        logger.error('User cache invalidation error', { error });
    }
};

export const getAllUsers = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 10,
            search = '',
            role = '',
            isActive = ''
        } = req.query;

        const cacheKey = `${CACHE_KEYS.USERS_LIST}:${page}:${limit}:${search}:${role}:${isActive}`;

        // بررسی کش
        const cached = await cacheGet(cacheKey);
        if (cached) {
            logger.debug('Serving users list from cache', { cacheKey });
            return res.json({
                ...cached,
                fromCache: true
            });
        }

        // ساخت شرط جستجو
        const searchFilter: any = {};

        if (search) {
            searchFilter.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ];
        }

        if (role) {
            searchFilter.role = role;
        } else {
            // به طور پیش‌فرض، کاربران معمولی و ادمین‌ها را نشان بده
            searchFilter.role = { $in: ['user', 'admin'] };
        }

        if (isActive !== '') {
            searchFilter.isActive = isActive === 'true';
        }

        // کاربران را بگیر (به جز خود کاربر فعلی)
        searchFilter._id = { $ne: req.userId };

        const users = await User.find(searchFilter)
            .select('-password -emailVerificationCode -emailVerificationCodeExpires')
            .sort({ createdAt: -1 })
            .limit(Number(limit))
            .skip((Number(page) - 1) * Number(limit));

        const total = await User.countDocuments(searchFilter);

        const responseData = {
            success: true,
            users,
            pagination: {
                total,
                page: Number(page),
                limit: Number(limit),
                totalPages: Math.ceil(total / Number(limit))
            }
        };

        // ذخیره در کش
        await cacheSet(cacheKey, responseData, CACHE_TTL.SHORT);

        LoggerService.userLog(req.userId!, 'get_all_users', {
            page,
            limit,
            search,
            total
        });

        res.json({
            ...responseData,
            fromCache: false
        });

    } catch (error) {
        LoggerService.errorLog('getAllUsers', error, {
            userId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت لیست کاربران'
        });
    }
};

export const getUserById = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const cacheKey = `${CACHE_KEYS.USER_DETAIL}:${id}`;

        // بررسی کش
        const cached = await cacheGet(cacheKey);
        if (cached) {
            LoggerService.userLog(req.userId!, 'get_user_by_id', {
                targetUserId: id,
                fromCache: true
            });
            return res.json({
                success: true,
                user: cached,
                fromCache: true
            });
        }

        const user = await User.findById(id)
            .select('-password -emailVerificationCode -emailVerificationCodeExpires');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'کاربر یافت نشد'
            });
        }

        // ذخیره در کش
        await cacheSet(cacheKey, user, CACHE_TTL.MEDIUM);

        LoggerService.userLog(req.userId!, 'get_user_by_id', {
            targetUserId: id
        });

        res.json({
            success: true,
            user,
            fromCache: false
        });

    } catch (error) {
        LoggerService.errorLog('getUserById', error, {
            userId: req.userId,
            targetUserId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت اطلاعات کاربر'
        });
    }
};

export const loginAsUser = async (req: AuthRequest, res: Response) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'آیدی کاربر الزامی است'
            });
        }

        const cacheKey = `${CACHE_KEYS.USER_DETAIL}:${userId}`;

        // بررسی کش برای اطلاعات کاربر
        let targetUser = await cacheGet(cacheKey);
        if (!targetUser) {
            // اگر در کش نیست، از دیتابیس بگیر
            targetUser = await User.findById(userId);
            if (targetUser) {
                await cacheSet(cacheKey, targetUser, CACHE_TTL.MEDIUM);
            }
        }

        if (!targetUser) {
            return res.status(404).json({
                success: false,
                message: 'کاربر یافت نشد'
            });
        }

        // بررسی اینکه کاربر غیرفعال نباشد
        if (!targetUser.isActive) {
            return res.status(400).json({
                success: false,
                message: 'این کاربر غیرفعال است'
            });
        }

        // پیدا کردن ادمین/سوپر ادمین فعلی
        const currentAdmin = await User.findById(req.userId);
        if (!currentAdmin || (currentAdmin.role !== 'admin' && currentAdmin.role !== 'super_admin')) {
            return res.status(403).json({
                success: false,
                message: 'فقط ادمین‌ها مجاز به این عمل هستند'
            });
        }

        // ایجاد توکن برای کاربر هدف
        const token = jwt.sign(
            {
                userId: targetUser._id.toString(),
                impersonatedBy: currentAdmin._id.toString(),
                originalRole: targetUser.role
            },
            process.env.JWT_SECRET!,
            { expiresIn: '1h' }
        );

        // ذخیره session در Redis
        const sessionKey = `${CACHE_KEYS.USER_SESSION}:${targetUser._id.toString()}`;
        await cacheSet(sessionKey, {
            adminId: currentAdmin._id.toString(),
            impersonatedAt: new Date().toISOString(),
            originalRole: targetUser.role
        }, 3600); // 1 ساعت

        LoggerService.userLog(req.userId!, 'login_as_user', {
            targetUserId: userId,
            targetUserEmail: targetUser.email,
            adminEmail: currentAdmin.email,
            adminRole: currentAdmin.role
        });

        logger.info('Admin logged in as user', {
            adminId: currentAdmin._id.toString(),
            adminRole: currentAdmin.role,
            targetUserId: targetUser._id.toString(),
            targetUserEmail: targetUser.email
        });

        res.json({
            success: true,
            message: `ورود به حساب ${targetUser.name} با موفقیت انجام شد`,
            token,
            user: {
                id: targetUser._id.toString(),
                name: targetUser.name,
                email: targetUser.email,
                role: targetUser.role,
                authProvider: targetUser.authProvider,
                emailVerified: targetUser.emailVerified
            }
        });

    } catch (error) {
        LoggerService.errorLog('loginAsUser', error, {
            adminId: req.userId,
            targetUserId: req.body.userId
        });
        res.status(500).json({
            success: false,
            message: 'خطا در ورود به حساب کاربر'
        });
    }
};

export const updateUserStatus = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const { isActive } = req.body;

        // جلوگیری از غیرفعال کردن خود
        if (id === req.userId) {
            return res.status(400).json({
                success: false,
                message: 'نمی‌توانید وضعیت خودتان را تغییر دهید'
            });
        }

        const user = await User.findByIdAndUpdate(
            id,
            { isActive },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'کاربر یافت نشد'
            });
        }

        // 🔥 حذف کش مرتبط
        await invalidateUserCache(id);

        LoggerService.userLog(req.userId!, 'update_user_status', {
            targetUserId: id,
            newStatus: isActive ? 'active' : 'inactive'
        });

        res.json({
            success: true,
            message: `وضعیت کاربر ${isActive ? 'فعال' : 'غیرفعال'} شد`,
            user
        });

    } catch (error) {
        LoggerService.errorLog('updateUserStatus', error, {
            adminId: req.userId,
            targetUserId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'خطا در تغییر وضعیت کاربر'
        });
    }
};

export const getUserStats = async (req: AuthRequest, res: Response) => {
    try {
        const currentAdmin = await User.findById(req.userId);
        const cacheKey = `${CACHE_KEYS.USER_STATS}:${currentAdmin?.role}`;

        // بررسی کش
        const cached = await cacheGet(cacheKey);
        if (cached) {
            return res.json({
                success: true,
                stats: cached,
                fromCache: true
            });
        }

        let userFilter: any = { _id: { $ne: req.userId } };

        // اگر ادمین معمولی است، فقط کاربران معمولی را نشان بده
        if (currentAdmin?.role === 'admin') {
            userFilter.role = 'user';
        }

        const totalUsers = await User.countDocuments(userFilter);
        const activeUsers = await User.countDocuments({ ...userFilter, isActive: true });
        const adminsCount = await User.countDocuments({ role: 'admin' });

        // آمار کاربران جدید در 30 روز گذشته
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const newUsers = await User.countDocuments({
            ...userFilter,
            createdAt: { $gte: thirtyDaysAgo }
        });

        const stats = {
            totalUsers,
            activeUsers,
            inactiveUsers: totalUsers - activeUsers,
            adminsCount: currentAdmin?.role === 'super_admin' ? adminsCount : undefined,
            newUsersLast30Days: newUsers
        };

        // ذخیره در کش
        await cacheSet(cacheKey, stats, CACHE_TTL.SHORT);

        res.json({
            success: true,
            stats,
            fromCache: false
        });

    } catch (error) {
        LoggerService.errorLog('getUserStats', error, {
            userId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'خطا در دریافت آمار کاربران'
        });
    }
};

// 🆕 تابع برای دریافت اطلاعات session از Redis
export const getImpersonationSession = async (userId: string): Promise<any> => {
    try {
        const sessionKey = `${CACHE_KEYS.USER_SESSION}:${userId}`;
        return await cacheGet(sessionKey);
    } catch (error) {
        logger.error('Error getting impersonation session', { userId, error });
        return null;
    }
};

// 🆕 تابع برای حذف session از Redis
export const clearImpersonationSession = async (userId: string): Promise<void> => {
    try {
        const sessionKey = `${CACHE_KEYS.USER_SESSION}:${userId}`;
        await redisClient.del(sessionKey);
        logger.debug('Impersonation session cleared', { userId });
    } catch (error) {
        logger.error('Error clearing impersonation session', { userId, error });
    }
};