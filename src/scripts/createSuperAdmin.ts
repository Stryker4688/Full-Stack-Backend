// backend/src/scripts/createSuperAdmin.ts
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import User from '../models/users';
import { logger } from '../config/logger';
import { cacheDeletePattern } from '../utils/cacheUtils';

// Create super admin user if it doesn't exist
export const createSuperAdmin = async (): Promise<void> => {
    try {
        const superAdminEmail = process.env.SUPER_ADMIN_EMAIL || 'superadmin@coffee-shop.com';
        const superAdminPassword = process.env.SUPER_ADMIN_PASSWORD || 'SuperAdmin123!';

        // Check if super admin already exists - without cache
        const existingSuperAdmin = await User.findOne({
            email: superAdminEmail.toLowerCase(),
            role: 'super_admin'
        });

        if (existingSuperAdmin) {
            logger.info('Super admin already exists', {
                email: superAdminEmail,
                userId: existingSuperAdmin._id.toString()
            });
            return;
        }

        // Hash password with pepper for additional security
        const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
            .update(superAdminPassword)
            .digest('hex');
        const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

        // Create super admin user
        const superAdmin = new User({
            name: 'Super Admin',
            email: superAdminEmail.toLowerCase(),
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

        // Display credentials in console (for initial setup)
        console.log('🎯 Super Admin Credentials:');
        console.log('📧 Email:', superAdminEmail);
        console.log('🔑 Password:', superAdminPassword);
        console.log('⚠️  Remember to change the password after first login!');

    } catch (error: any) {
        logger.error('Failed to create super admin', { error: error.message });
        console.error('❌ Error creating super admin:', error.message);
    }
};

// Check if super admin exists in database
export const checkSuperAdmin = async (): Promise<void> => {
    try {
        const superAdminCount = await User.countDocuments({ role: 'super_admin' });

        if (superAdminCount === 0) {
            logger.warn('No super admin found in database');
            console.log('⚠️  No super admin found. Run createSuperAdmin script.');
        } else {
            logger.info('Super admin check completed', { count: superAdminCount });
        }
    } catch (error: any) {
        logger.error('Failed to check super admin', { error: error.message });
    }
};