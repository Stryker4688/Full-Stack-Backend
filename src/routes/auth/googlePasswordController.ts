// backend/src/controllers/googlePasswordController.ts
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import User from '../../models/users';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

export const setupGooglePassword = async (req: Request, res: Response) => {
    try {
        const { tempToken, password } = req.body;

        if (!tempToken || !password) {
            logger.warn('Google password setup - missing tempToken or password');
            return res.status(400).json({
                success: false,
                message: 'Temp token and password are required'
            });
        }

        if (password.length < 6) {
            logger.warn('Google password setup - password too short');
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long'
            });
        }

        // بررسی توکن موقت
        let decoded: any;
        try {
            decoded = jwt.verify(tempToken, process.env.JWT_SECRET!);
        } catch (error) {
            logger.warn('Google password setup - invalid or expired temp token');
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired temporary token'
            });
        }

        if (decoded.type !== 'google_password_setup') {
            logger.warn('Google password setup - invalid token type', { type: decoded.type });
            return res.status(401).json({
                success: false,
                message: 'Invalid token type'
            });
        }

        let user;
        let isNewUser = false;

        // اگر کاربر جدید است (دارای اطلاعات گوگل)
        if (decoded.googleUser) {
            const { googleUser } = decoded;

            // بررسی اینکه کاربر از قبل وجود ندارد (برای جلوگیری از duplicate)
            const existingUser = await User.findOne({
                email: googleUser.email
            });

            if (existingUser) {
                logger.warn('Google password setup - user already exists', { email: googleUser.email });
                return res.status(400).json({
                    success: false,
                    message: 'User already exists'
                });
            }

            // هش کردن رمز عبور
            const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
                .update(password)
                .digest('hex');
            const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

            // ایجاد کاربر جدید
            user = new User({
                googleId: googleUser.googleId,
                email: googleUser.email,
                name: googleUser.name,
                avatar: googleUser.picture,
                authProvider: 'google',
                emailVerified: googleUser.emailVerified,
                password: hashedPassword,
                lastLogin: new Date()
            });

            await user.save();
            isNewUser = true;

            LoggerService.authLog(user._id.toString(), 'google_registration_completed', {
                provider: 'google',
                email: user.email
            });

            logger.info('New Google user registration completed', {
                userId: user._id.toString(),
                email: user.email
            });

        }
        // اگر کاربر موجود است (به روزرسانی رمز عبور)
        else if (decoded.userId) {
            user = await User.findById(decoded.userId);

            if (!user) {
                logger.warn('Google password setup - user not found', { userId: decoded.userId });
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // هش کردن رمز عبور جدید
            const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
                .update(password)
                .digest('hex');
            const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

            // به روزرسانی رمز عبور
            user.password = hashedPassword;
            user.lastLogin = new Date();
            await user.save();

            LoggerService.authLog(user._id.toString(), 'google_password_setup', {
                provider: 'google',
                email: user.email
            });

            logger.info('Google user password setup completed', {
                userId: user._id.toString(),
                email: user.email
            });
        } else {
            logger.warn('Google password setup - invalid token data');
            return res.status(400).json({
                success: false,
                message: 'Invalid token data'
            });
        }

        // تولید توکن اصلی
        const token = jwt.sign(
            { userId: user._id.toString() },
            process.env.JWT_SECRET!,
            { expiresIn: '120d' }
        );

        logger.info('Google password setup completed successfully', {
            userId: user._id.toString(),
            isNewUser
        });

        res.json({
            success: true,
            message: isNewUser ? 'Registration completed successfully' : 'Password set successfully',
            token,
            expiresIn: '120d',
            user: {
                id: user._id.toString(),
                name: user.name,
                email: user.email,
                role: user.role,
                authProvider: user.authProvider,
                emailVerified: user.emailVerified
            }
        });

    } catch (error: any) {
        logger.error('Google password setup failed', {
            error: error.message,
            stack: error.stack
        });
        res.status(500).json({
            success: false,
            message: 'Password setup failed',
            error: error.message
        });
    }
};