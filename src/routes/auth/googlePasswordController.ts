// backend/src/controllers/googlePasswordController.ts - Optimized with Redis
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import User from '../../models/users';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { clearUserCache, cacheDeletePattern } from '../../utils/cacheUtils';

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

        if (decoded.googleUser) {
            const { googleUser } = decoded;

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

            const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
                .update(password)
                .digest('hex');
            const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

            user = new User({
                googleId: googleUser.googleId,
                email: googleUser.email,
                name: googleUser.name,
                avatar: googleUser.picture,
                authProvider: 'google',
                emailVerified: true,
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

        } else if (decoded.userId) {
            user = await User.findById(decoded.userId);

            if (!user) {
                logger.warn('Google password setup - user not found', { userId: decoded.userId });
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
                .update(password)
                .digest('hex');
            const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

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

        // Clear user cache
        await clearUserCache(user._id.toString());

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
                emailVerified: true
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