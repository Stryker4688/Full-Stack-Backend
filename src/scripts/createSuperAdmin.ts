// backend/src/scripts/createSuperAdmin.ts - Optimized
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import User from '../models/users';
import { logger } from '../config/logger';
import { clearUserCache, cacheDeletePattern } from '../utils/cacheUtils';

export const createSuperAdmin = async (): Promise<void> => {
    try {
        const superAdminEmail = process.env.SUPER_ADMIN_EMAIL || 'superadmin@coffee-shop.com';
        const superAdminPassword = process.env.SUPER_ADMIN_PASSWORD || 'SuperAdmin123!';

        // Check if super admin already exists
        const existingSuperAdmin = await User.findOne({
            email: superAdminEmail,
            role: 'super_admin'
        });

        if (existingSuperAdmin) {
            logger.info('Super admin already exists', {
                email: superAdminEmail,
                userId: existingSuperAdmin._id.toString()
            });
            return;
        }

        // Hash password
        const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
            .update(superAdminPassword)
            .digest('hex');
        const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

        // Create super admin
        const superAdmin = new User({
            name: 'Super Admin',
            email: superAdminEmail,
            password: hashedPassword,
            role: 'super_admin',
            emailVerified: true,
            isActive: true
        });

        await superAdmin.save();

        // Clear any user caches
        await cacheDeletePattern('users:*');
        await cacheDeletePattern('admins:*');

        logger.info('Super admin created successfully', {
            email: superAdminEmail,
            userId: superAdmin._id.toString()
        });

        console.log('🎯 Super Admin Credentials:');
        console.log('📧 Email:', superAdminEmail);
        console.log('🔑 Password:', superAdminPassword);
        console.log('⚠️  Remember to change the password after first login!');

    } catch (error) {
        logger.error('Failed to create super admin', { error });
        console.error('❌ Error creating super admin:', error);
    }
};

export const checkSuperAdmin = async (): Promise<void> => {
    try {
        const superAdminCount = await User.countDocuments({ role: 'super_admin' });

        if (superAdminCount === 0) {
            logger.warn('No super admin found in database');
            console.log('⚠️  No super admin found. Run createSuperAdmin script.');
        } else {
            logger.info('Super admin check completed', { count: superAdminCount });
        }
    } catch (error) {
        logger.error('Failed to check super admin', { error });
    }
};