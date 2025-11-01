// backend/src/scripts/createSuperAdmin.ts
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import User from '../models/users';
import dotenv from 'dotenv';

dotenv.config();

async function createSuperAdmin() {
    try {
        // اتصال به دیتابیس
        await mongoose.connect(process.env.DATABASE_URL!);
        console.log('✅ Connected to MongoDB');

        // چک کردن وجود سوپر ادمین
        const existingAdmin = await User.findOne({
            email: process.env.SUPER_ADMIN_EMAIL
        });

        if (existingAdmin) {
            console.log('✅ Super admin already exists');
            return;
        }

        // ایجاد سوپر ادمین جدید
        const hashedPassword = await bcrypt.hash(process.env.SUPER_ADMIN_PASSWORD!, 12);

        const superAdmin = new User({
            name: 'Super Admin',
            email: process.env.SUPER_ADMIN_EMAIL,
            password: hashedPassword,
            role: 'super_admin',
            isActive: true,
            emailVerified: true,
        });

        await superAdmin.save();
        console.log('🎉 Super admin created successfully!');

    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    } finally {
        await mongoose.disconnect();
    }
}

createSuperAdmin();