// backend/src/controllers/userManagementController.ts - Optimized with Redis
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import User from '../../models/users';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import jwt from 'jsonwebtoken';
import { cacheWithFallback, generateKey, CACHE_TTL, clearUserCache, cacheDeletePattern } from '../../utils/cacheUtils';

export const getAllUsers = async (req: AuthRequest, res: Response) => {
    try {
        const {
            page = 1,
            limit = 10,
            search = '',
            role = '',
            isActive = ''
        } = req.query;

        const cacheKey = generateKey.userList(`page:${page}:limit:${limit}:search:${search}:role:${role}:active:${isActive}`);

        const responseData = await cacheWithFallback(
            cacheKey,
            async () => {
                // Build search filter
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
                    searchFilter.role = { $in: ['user', 'admin'] };
                }

                if (isActive !== '') {
                    searchFilter.isActive = isActive === 'true';
                }

                // Exclude current user
                searchFilter._id = { $ne: req.userId };

                const users = await User.find(searchFilter)
                    .select('-password -emailVerificationCode -emailVerificationCodeExpires')
                    .sort({ createdAt: -1 })
                    .limit(Number(limit))
                    .skip((Number(page) - 1) * Number(limit));

                const total = await User.countDocuments(searchFilter);

                return {
                    success: true,
                    users,
                    pagination: {
                        total,
                        page: Number(page),
                        limit: Number(limit),
                        totalPages: Math.ceil(total / Number(limit))
                    }
                };
            },
            CACHE_TTL.SHORT
        );

        LoggerService.userLog(req.userId!, 'get_all_users', {
            page,
            limit,
            search,
            total: responseData.pagination.total
        });

        res.json(responseData);

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

        const user = await cacheWithFallback(
            generateKey.userProfile(id),
            async () => await User.findById(id)
                .select('-password -emailVerificationCode -emailVerificationCodeExpires'),
            CACHE_TTL.USER_PROFILE
        );

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'کاربر یافت نشد'
            });
        }

        LoggerService.userLog(req.userId!, 'get_user_by_id', {
            targetUserId: id
        });

        res.json({
            success: true,
            user
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

        // Find target user with cache
        const targetUser = await cacheWithFallback(
            generateKey.userProfile(userId),
            async () => await User.findById(userId),
            CACHE_TTL.SHORT
        );

        if (!targetUser) {
            return res.status(404).json({
                success: false,
                message: 'کاربر یافت نشد'
            });
        }

        if (!targetUser.isActive) {
            return res.status(400).json({
                success: false,
                message: 'این کاربر غیرفعال است'
            });
        }

        // Find current admin
        const currentAdmin = await User.findById(req.userId);
        if (!currentAdmin || (currentAdmin.role !== 'admin' && currentAdmin.role !== 'super_admin')) {
            return res.status(403).json({
                success: false,
                message: 'فقط ادمین‌ها مجاز به این عمل هستند'
            });
        }

        // Create token for target user
        const token = jwt.sign(
            {
                userId: targetUser._id.toString(),
                impersonatedBy: currentAdmin._id.toString(),
                originalRole: targetUser.role
            },
            process.env.JWT_SECRET!,
            { expiresIn: '1h' }
        );

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

        // Prevent self-deactivation
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

        // Clear user cache and user list caches
        await clearUserCache(id);
        await cacheDeletePattern('users:list:*');

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
        const cacheKey = generateKey.userStats();

        const stats = await cacheWithFallback(
            cacheKey,
            async () => {
                const currentAdmin = await User.findById(req.userId);

                let userFilter: any = { _id: { $ne: req.userId } };

                // If regular admin, only show regular users
                if (currentAdmin?.role === 'admin') {
                    userFilter.role = 'user';
                }

                const totalUsers = await User.countDocuments(userFilter);
                const activeUsers = await User.countDocuments({ ...userFilter, isActive: true });
                const adminsCount = await User.countDocuments({ role: 'admin' });

                // New users in last 30 days
                const thirtyDaysAgo = new Date();
                thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

                const newUsers = await User.countDocuments({
                    ...userFilter,
                    createdAt: { $gte: thirtyDaysAgo }
                });

                return {
                    totalUsers,
                    activeUsers,
                    inactiveUsers: totalUsers - activeUsers,
                    adminsCount: currentAdmin?.role === 'super_admin' ? adminsCount : undefined,
                    newUsersLast30Days: newUsers
                };
            },
            CACHE_TTL.MEDIUM
        );

        res.json({
            success: true,
            stats
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