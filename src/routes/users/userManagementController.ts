// backend/src/controllers/userManagementController.ts - Fixed version
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import User from '../../models/users';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import jwt from 'jsonwebtoken';
import { cacheWithFallback, generateKey, CACHE_TTL, clearUserCache, cacheDeletePattern } from '../../utils/cacheUtils';

// Get all users with pagination and filtering
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

                // Exclude current user from results
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

    } catch (error: any) {
        LoggerService.errorLog('getAllUsers', error, {
            userId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'Error retrieving user list'
        });
    }
};

// Get user by ID
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
                message: 'User not found'
            });
        }

        LoggerService.userLog(req.userId!, 'get_user_by_id', {
            targetUserId: id
        });

        res.json({
            success: true,
            user
        });

    } catch (error: any) {
        LoggerService.errorLog('getUserById', error, {
            userId: req.userId,
            targetUserId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'Error retrieving user information'
        });
    }
};

// Admin login as user (impersonation)
export const loginAsUser = async (req: AuthRequest, res: Response) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }

        // Find target user - without cache for security
        const targetUser = await User.findById(userId)
            .select('-password -emailVerificationCode -emailVerificationCodeExpires');

        if (!targetUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (!targetUser.isActive) {
            return res.status(400).json({
                success: false,
                message: 'This user account is deactivated'
            });
        }

        // Find current admin to verify permissions
        const currentAdmin = await User.findById(req.userId);
        if (!currentAdmin || (currentAdmin.role !== 'admin' && currentAdmin.role !== 'super_admin')) {
            return res.status(403).json({
                success: false,
                message: 'Only admins are authorized for this action'
            });
        }

        // Create impersonation token for target user
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
            message: `Logged into ${targetUser.name}'s account successfully`,
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

    } catch (error: any) {
        LoggerService.errorLog('loginAsUser', error, {
            adminId: req.userId,
            targetUserId: req.body.userId
        });
        res.status(500).json({
            success: false,
            message: 'Error logging into user account'
        });
    }
};

// Update user active status
export const updateUserStatus = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const { isActive } = req.body;

        // Prevent self-deactivation
        if (id === req.userId) {
            return res.status(400).json({
                success: false,
                message: 'You cannot change your own status'
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
                message: 'User not found'
            });
        }

        // Clear user cache and user list caches
        await clearUserCache(id);
        await cacheDeletePattern('users:list:*');
        await cacheDeletePattern('users:stats*');

        LoggerService.userLog(req.userId!, 'update_user_status', {
            targetUserId: id,
            newStatus: isActive ? 'active' : 'inactive'
        });

        res.json({
            success: true,
            message: `User ${isActive ? 'activated' : 'deactivated'}`,
            user
        });

    } catch (error: any) {
        LoggerService.errorLog('updateUserStatus', error, {
            adminId: req.userId,
            targetUserId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'Error changing user status'
        });
    }
};

// Get user statistics for dashboard
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

    } catch (error: any) {
        LoggerService.errorLog('getUserStats', error, {
            userId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'Error retrieving user statistics'
        });
    }
};