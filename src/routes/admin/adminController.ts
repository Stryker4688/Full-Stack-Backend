// backend/src/controllers/adminController.ts - Optimized with cache utilities
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import User from '../../models/users';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import {
    cacheGet,
    cacheSet,
    cacheDelete,
    clearUserCache,
    clearAdminCache,
    generateKey,
    CACHE_TTL,
    cacheWithFallback
} from '../../utils/cacheUtils';

// Create new admin (super admin only)
export const createAdmin = async (req: AuthRequest, res: Response) => {
    try {
        const { name, email, password } = req.body;

        logger.info('Creating new admin account', {
            superAdminId: req.userId,
            adminEmail: email
        });

        // Check cache for existing user
        const userCacheKey = generateKey.userProfile(email);
        const existingUserCached = await cacheGet(userCacheKey);

        if (existingUserCached) {
            return res.status(400).json({
                success: false,
                message: 'User with this email already exists'
            });
        }

        // Check database for existing user
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            // Cache existence to prevent duplicate checks
            await cacheSet(userCacheKey, { exists: true }, CACHE_TTL.SHORT);

            return res.status(400).json({
                success: false,
                message: 'User with this email already exists'
            });
        }

        // Hash password with pepper
        const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
            .update(password)
            .digest('hex');
        const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

        // Create admin user
        const admin = new User({
            name,
            email,
            password: hashedPassword,
            role: 'admin',
            emailVerified: true
        });

        await admin.save();

        // Clear admin cache to reflect new admin
        await clearAdminCache();

        // Cache new admin information
        await cacheSet(generateKey.userDetail(admin._id.toString()), {
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
            success: true,
            message: 'Admin account created successfully',
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
        res.status(500).json({
            success: false,
            message: 'Error creating admin account',
            error
        });
    }
};

// Get all admins with pagination
export const getAdmins = async (req: AuthRequest, res: Response) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const cacheKey = generateKey.adminList(Number(page), Number(limit));

        const result = await cacheWithFallback(
            cacheKey,
            async () => {
                // Get only admin accounts (not super_admins)
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

                return {
                    admins,
                    totalPages: Math.ceil(total / Number(limit)),
                    currentPage: Number(page),
                    total
                };
            },
            CACHE_TTL.SHORT
        );

        logger.debug('Admins list retrieved', {
            superAdminId: req.userId,
            count: result.admins.length
        });

        res.json({
            success: true,
            ...result
        });

    } catch (error) {
        LoggerService.errorLog('getAdmins', error, {
            superAdminId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'Error retrieving admins list',
            error
        });
    }
};

// Delete admin account
export const deleteAdmin = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        // Prevent self-deletion
        if (id === req.userId) {
            return res.status(400).json({
                success: false,
                message: 'You cannot delete your own account'
            });
        }

        const admin = await User.findOneAndDelete({
            _id: id,
            role: 'admin'
        });

        if (!admin) {
            return res.status(404).json({
                success: false,
                message: 'Admin not found'
            });
        }

        // Clear all relevant caches
        await Promise.all([
            clearUserCache(id),
            clearAdminCache(),
            cacheDelete(generateKey.userDetail(id)),
            cacheDelete(generateKey.userProfile(admin.email))
        ]);

        LoggerService.userLog(req.userId!, 'delete_admin', {
            adminId: id,
            adminEmail: admin.email
        });

        logger.info('Admin deleted successfully', {
            superAdminId: req.userId,
            adminId: id
        });

        res.json({
            success: true,
            message: 'Admin account deleted successfully'
        });

    } catch (error) {
        LoggerService.errorLog('deleteAdmin', error, {
            superAdminId: req.userId,
            adminId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'Error deleting admin account',
            error
        });
    }
};

// Toggle admin status (activate/deactivate)
export const toggleAdminStatus = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        const admin = await User.findOne({
            _id: id,
            role: 'admin'
        });

        if (!admin) {
            return res.status(404).json({
                success: false,
                message: 'Admin not found'
            });
        }

        admin.isActive = !admin.isActive;
        await admin.save();

        // Update admin cache
        await cacheSet(generateKey.userDetail(id), {
            id: admin._id.toString(),
            name: admin.name,
            email: admin.email,
            role: admin.role,
            isActive: admin.isActive
        }, CACHE_TTL.MEDIUM);

        // Clear admin list cache
        await clearAdminCache();

        LoggerService.userLog(req.userId!, 'toggle_admin_status', {
            adminId: id,
            newStatus: admin.isActive ? 'active' : 'inactive'
        });

        logger.info('Admin status updated', {
            superAdminId: req.userId,
            adminId: id,
            isActive: admin.isActive
        });

        res.json({
            success: true,
            message: `Admin account ${admin.isActive ? 'activated' : 'deactivated'} successfully`,
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
        res.status(500).json({
            success: false,
            message: 'Error updating admin status',
            error
        });
    }
};

// Get super admins list
export const getSuperAdmins = async (req: AuthRequest, res: Response) => {
    try {
        const cacheKey = 'super_admins_list';

        const superAdmins = await cacheWithFallback(
            cacheKey,
            async () => {
                const superAdmins = await User.find({ role: 'super_admin' })
                    .select('name email isActive createdAt lastLogin')
                    .sort({ createdAt: -1 });

                return superAdmins;
            },
            CACHE_TTL.LONG
        );

        res.json({
            success: true,
            superAdmins
        });

    } catch (error) {
        LoggerService.errorLog('getSuperAdmins', error, {
            superAdminId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'Error retrieving super admins list'
        });
    }
};

// Get admin statistics
export const getAdminStats = async (req: AuthRequest, res: Response) => {
    try {
        const cacheKey = 'admin_stats';

        const stats = await cacheWithFallback(
            cacheKey,
            async () => {
                const totalAdmins = await User.countDocuments({ role: 'admin' });
                const activeAdmins = await User.countDocuments({ role: 'admin', isActive: true });
                const totalSuperAdmins = await User.countDocuments({ role: 'super_admin' });

                // New admins in last 30 days
                const thirtyDaysAgo = new Date();
                thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

                const newAdmins = await User.countDocuments({
                    role: 'admin',
                    createdAt: { $gte: thirtyDaysAgo }
                });

                return {
                    totalAdmins,
                    activeAdmins,
                    inactiveAdmins: totalAdmins - activeAdmins,
                    totalSuperAdmins,
                    newAdminsLast30Days: newAdmins
                };
            },
            CACHE_TTL.SHORT
        );

        res.json({
            success: true,
            stats
        });

    } catch (error) {
        LoggerService.errorLog('getAdminStats', error, {
            superAdminId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'Error retrieving admin statistics'
        });
    }
};