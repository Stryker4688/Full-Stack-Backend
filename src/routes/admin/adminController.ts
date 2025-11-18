// backend/src/controllers/adminController.ts - Fixed version
import { Response } from 'express';
import { AuthRequest } from '../../middlewares/auth';
import User from '../../models/users';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { clearUserCache, cacheWithFallback, generateKey, CACHE_TTL, cacheDeletePattern } from '../../utils/cacheUtils';

// Create new admin user (Super Admin only)
export const createAdmin = async (req: AuthRequest, res: Response) => {
    try {
        const { name, email, password } = req.body;

        logger.info('Creating new admin', {
            superAdminId: req.userId,
            adminEmail: email
        });

        // Check existing user - without cache for security
        const existingUser = await User.findOne({ email: email.toLowerCase() });

        if (existingUser) {
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
            email: email.toLowerCase(),
            password: hashedPassword,
            role: 'admin',
            emailVerified: true
        });

        await admin.save();

        // Clear relevant caches
        await cacheDeletePattern('admins:*');
        await cacheDeletePattern('users:list:*');
        await cacheDeletePattern('users:stats*');

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
            message: 'Admin created successfully',
            admin: {
                id: admin._id.toString(),
                name: admin.name,
                email: admin.email,
                role: admin.role,
                isActive: admin.isActive,
                createdAt: admin.createdAt
            }
        });

    } catch (error: any) {
        LoggerService.errorLog('createAdmin', error, {
            superAdminId: req.userId,
            adminData: req.body
        });
        res.status(500).json({
            success: false,
            message: 'Error creating admin',
            error: error.message
        });
    }
};

// Get list of all admins
export const getAdmins = async (req: AuthRequest, res: Response) => {
    try {
        const { page = 1, limit = 10 } = req.query;

        const cacheKey = generateKey.adminList(Number(page), Number(limit));

        const result = await cacheWithFallback(
            cacheKey,
            async () => {
                const admins = await User.find({
                    role: 'admin'
                })
                    .select('-password -emailVerificationCode -emailVerificationCodeExpires')
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
            CACHE_TTL.MEDIUM
        );

        logger.debug('Admins list fetched', {
            superAdminId: req.userId,
            count: result.admins.length
        });

        res.json({
            success: true,
            ...result
        });

    } catch (error: any) {
        LoggerService.errorLog('getAdmins', error, {
            superAdminId: req.userId
        });
        res.status(500).json({
            success: false,
            message: 'Error retrieving admin list',
            error: error.message
        });
    }
};

// Delete admin user
export const deleteAdmin = async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        // Prevent self-deletion
        if (id === req.userId) {
            return res.status(400).json({
                success: false,
                message: 'You cannot delete yourself'
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
        await clearUserCache(id);
        await cacheDeletePattern('admins:*');
        await cacheDeletePattern('users:list:*');
        await cacheDeletePattern('users:stats*');

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
            message: 'Admin deleted successfully'
        });

    } catch (error: any) {
        LoggerService.errorLog('deleteAdmin', error, {
            superAdminId: req.userId,
            adminId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'Error deleting admin',
            error: error.message
        });
    }
};

// Toggle admin active status
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

        // Clear relevant caches
        await clearUserCache(id);
        await cacheDeletePattern('admins:*');
        await cacheDeletePattern('users:list:*');
        await cacheDeletePattern('users:stats*');

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
            success: true,
            message: `Admin ${admin.isActive ? 'activated' : 'deactivated'}`,
            admin: {
                id: admin._id.toString(),
                name: admin.name,
                email: admin.email,
                isActive: admin.isActive
            }
        });

    } catch (error: any) {
        LoggerService.errorLog('toggleAdminStatus', error, {
            superAdminId: req.userId,
            adminId: req.params.id
        });
        res.status(500).json({
            success: false,
            message: 'Error changing admin status',
            error: error.message
        });
    }
};