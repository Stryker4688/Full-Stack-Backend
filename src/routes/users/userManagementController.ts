// backend/src/controllers/userManagementController.ts - Optimized with cache utilities
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import User from '../../models/users';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import jwt from 'jsonwebtoken';
import {
    cacheGet,
    cacheSet,
    cacheDelete,
    clearUserCache,
    generateKey,
    CACHE_TTL,
    cacheWithFallback
} from '../../utils/cacheUtils';

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

        const cacheKey = `users_list:${page}:${limit}:${search}:${role}:${isActive}`;

        const responseData = await cacheWithFallback(
            cacheKey,
            async () => {
                // Build search filter
                const searchFilter: any = {};

                // Exclude current admin from results
                searchFilter._id = { $ne: req.userId };

                // Search by name or email
                if (search) {
                    searchFilter.$or = [
                        { name: { $regex: search, $options: 'i' } },
                        { email: { $regex: search, $options: 'i' } }
                    ];
                }

                // Filter by role
                if (role) {
                    searchFilter.role = role;
                } else {
                    // Default: show regular users and admins (not super_admins)
                    searchFilter.role = { $in: ['user', 'admin'] };
                }

                // Filter by active status
                if (isActive !== '') {
                    searchFilter.isActive = isActive === 'true';
                }

                // Get users with pagination
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
            message: 'Error retrieving users list'
        });
    }
};

// Get user by ID
export const getUserById = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const cacheKey = generateKey.userDetail(id);

        const user = await cacheWithFallback(
            cacheKey,
            async () => {
                const user = await User.findById(id)
                    .select('-password -emailVerificationCode -emailVerificationCodeExpires');

                if (!user) {
                    throw new Error('User not found');
                }

                return user;
            },
            CACHE_TTL.MEDIUM
        );

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

        // Get target user information
        const targetUser = await cacheWithFallback(
            generateKey.userDetail(userId),
            async () => {
                const user = await User.findById(userId);
                if (!user) {
                    throw new Error('User not found');
                }
                return user;
            },
            CACHE_TTL.MEDIUM
        );

        // Check if target user is active
        if (!targetUser.isActive) {
            return res.status(400).json({
                success: false,
                message: 'This user account is deactivated'
            });
        }

        // Verify current admin permissions
        const currentAdmin = await User.findById(req.userId);
        if (!currentAdmin || (currentAdmin.role !== 'admin' && currentAdmin.role !== 'super_admin')) {
            return res.status(403).json({
                success: false,
                message: 'Only administrators are authorized for this action'
            });
        }

        // Generate impersonation token
        const token = jwt.sign(
            {
                userId: targetUser._id.toString(),
                impersonatedBy: currentAdmin._id.toString(),
                originalRole: targetUser.role
            },
            process.env.JWT_SECRET!,
            { expiresIn: '1h' }
        );

        // Store impersonation session in cache
        const sessionKey = generateKey.userSession(targetUser._id.toString());
        await cacheSet(sessionKey, {
            adminId: currentAdmin._id.toString(),
            impersonatedAt: new Date().toISOString(),
            originalRole: targetUser.role
        }, 3600); // 1 hour TTL

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
            message: `Successfully logged in as ${targetUser.name}`,
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
            message: 'Error during user impersonation'
        });
    }
};

// Update user status (activate/deactivate)
export const updateUserStatus = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const { isActive } = req.body;

        // Prevent self-deactivation
        if (id === req.userId) {
            return res.status(400).json({
                success: false,
                message: 'You cannot change your own account status'
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

        // Clear user cache to reflect status change
        await clearUserCache(id);

        LoggerService.userLog(req.userId!, 'update_user_status', {
            targetUserId: id,
            newStatus: isActive ? 'active' : 'inactive'
        });

        res.json({
            success: true,
            message: `User account ${isActive ? 'activated' : 'deactivated'} successfully`,
            user
        });

    } catch (error) {
        LoggerService.errorLog('updateUserStatus', error, {
            adminId: req.userId,
            targetUserId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'Error updating user status'
        });
    }
};

// Get user statistics for dashboard
export const getUserStats = async (req: AuthRequest, res: Response) => {
    try {
        const currentAdmin = await User.findById(req.userId);
        const cacheKey = `user_stats:${currentAdmin?.role}`;

        const stats = await cacheWithFallback(
            cacheKey,
            async () => {
                let userFilter: any = { _id: { $ne: req.userId } };

                // Regular admins can only see regular users
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

                const stats: any = {
                    totalUsers,
                    activeUsers,
                    inactiveUsers: totalUsers - activeUsers,
                    newUsersLast30Days: newUsers
                };

                // Only super admin can see admin counts
                if (currentAdmin?.role === 'super_admin') {
                    stats.adminsCount = adminsCount;
                }

                return stats;
            },
            CACHE_TTL.SHORT
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
            message: 'Error retrieving user statistics'
        });
    }
};

// Get impersonation session from cache
export const getImpersonationSession = async (userId: string): Promise<any> => {
    try {
        const sessionKey = generateKey.userSession(userId);
        return await cacheGet(sessionKey);
    } catch (error) {
        logger.error('Error getting impersonation session', {
            userId,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
        return null;
    }
};

// Clear impersonation session
export const clearImpersonationSession = async (userId: string): Promise<void> => {
    try {
        const sessionKey = generateKey.userSession(userId);
        await cacheDelete(sessionKey);
        logger.debug('Impersonation session cleared', { userId });
    } catch (error) {
        logger.error('Error clearing impersonation session', {
            userId,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};