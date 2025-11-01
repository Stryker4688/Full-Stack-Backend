// backend/src/controllers/googleAuthController.ts
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import User from '../../models/users';
import { GoogleAuthService } from '../../services/googleAuthService';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { AuthRequest } from '../../middlewares/auth';

export const googleAuth = async (req: AuthRequest, res: Response) => {
    try {
        const { code, idToken, rememberMe = false } = req.body;

        logger.debug('Google auth attempt', {
            hasCode: !!code,
            hasToken: !!idToken
        });

        // ۱. بررسی وجود code یا token
        if (!code && !idToken) {
            logger.warn('Google auth failed - no code or token provided');
            return res.status(400).json({
                success: false,
                message: 'Google authorization code or token is required'
            });
        }

        let googleUser;
        let usedIdToken = '';

        // ۲. اگر code داریم، باید به idToken تبدیل کنیم
        if (code) {
            logger.debug('Processing authorization code flow');
            try {
                usedIdToken = await GoogleAuthService.getTokenFromCode(code);
                googleUser = await GoogleAuthService.verifyToken(usedIdToken);
            } catch (error: any) {
                logger.error('Failed to process authorization code', {
                    error: error.message
                });
                return res.status(400).json({
                    success: false,
                    message: `Invalid authorization code: ${error.message}`
                });
            }
        }
        // ۳. اگر مستقیم idToken داریم
        else if (idToken) {
            logger.debug('Processing direct token flow');
            usedIdToken = idToken;
            googleUser = await GoogleAuthService.verifyToken(idToken);
        }

        // ✅ بررسی وجود ایمیل (ضروری)
        if (!googleUser?.email) {
            logger.error('Google auth failed - no email in token');
            return res.status(400).json({
                success: false,
                message: 'Google account email is required'
            });
        }

        logger.debug('Google authentication successful', {
            email: googleUser.email,
            googleId: googleUser.googleId,
            flow: code ? 'authorization_code' : 'direct_token'
        });

        // ۴. پیدا کردن کاربر موجود
        let user = await User.findOne({
            $or: [
                { googleId: googleUser.googleId },
                { email: googleUser.email.toLowerCase() }
            ]
        });

        let requiresPasswordSetup = false;
        let tempToken = '';

        if (!user) {
            // 🆕 کاربر جدید - نیاز به تنظیم رمز عبور دارد
            logger.debug('New Google user - requiring password setup', {
                email: googleUser.email
            });

            // ایجاد یک توکن موقت برای تنظیم رمز عبور
            tempToken = jwt.sign(
                {
                    googleUser: {
                        googleId: googleUser.googleId,
                        email: googleUser.email.toLowerCase(),
                        name: googleUser.name || googleUser.email.split('@')[0],
                        picture: googleUser.picture,
                        emailVerified: googleUser.emailVerified || false
                    },
                    type: 'google_password_setup'
                },
                process.env.JWT_SECRET!,
                { expiresIn: '1h' } // توکن موقت 1 ساعته
            );

            requiresPasswordSetup = true;

            LoggerService.authLog('unknown', 'google_registration_pending', {
                provider: 'google',
                email: googleUser.email,
                requiresPasswordSetup: true
            });

        } else {
            // 🔄 کاربر موجود
            logger.debug('Existing user found for Google auth', {
                userId: user._id.toString(),
                existingProvider: user.authProvider
            });

            // اگر کاربر با ایمیل وجود داره اما Google auth نداره
            if (!user.googleId) {
                user.googleId = googleUser.googleId;
                user.authProvider = 'google';
            }

            // آپدیت lastLogin
            user.lastLogin = new Date();
            user.emailVerified = googleUser.emailVerified || false;

            await user.save();

            // اگر کاربر رمز عبور ندارد (کاربر قدیمی گوگل)، نیاز به تنظیم رمز عبور دارد
            if (!user.password) {
                tempToken = jwt.sign(
                    {
                        userId: user._id.toString(),
                        type: 'google_password_setup'
                    },
                    process.env.JWT_SECRET!,
                    { expiresIn: '1h' }
                );
                requiresPasswordSetup = true;
            }

            LoggerService.authLog(user._id.toString(), 'google_login', {
                provider: 'google',
                requiresPasswordSetup
            });
        }

        // ۵. اگر نیاز به تنظیم رمز عبور دارد
        if (requiresPasswordSetup) {
            logger.info('Google user requires password setup', {
                email: googleUser.email,
                isNewUser: !user
            });

            return res.json({
                success: true,
                requiresPasswordSetup: true,
                tempToken,
                message: 'Please set your password to complete registration',
                user: user ? {
                    id: user._id.toString(),
                    name: user.name,
                    email: user.email
                } : null
            });
        }

        // ۶. اگر کاربر کامل است و رمز عبور دارد
        const expiresIn = rememberMe ? '120d' : '1d';
        const token = jwt.sign(
            { userId: user!._id.toString() },
            process.env.JWT_SECRET!,
            { expiresIn }
        );

        logger.info('Google authentication successful', {
            userId: user!._id.toString(),
            email: user!.email,
            provider: 'google'
        });

        // ۷. پاسخ به فرانت‌اند
        res.json({
            success: true,
            requiresPasswordSetup: false,
            message: 'Login successful',
            token,
            expiresIn,
            user: {
                id: user!._id.toString(),
                name: user!.name,
                email: user!.email,
                role: user!.role,
                authProvider: user!.authProvider,
                emailVerified: user!.emailVerified
            }
        });

    } catch (error: any) {
        logger.error('Google authentication failed', {
            error: error.message,
            stack: error.stack
        });
        res.status(401).json({
            success: false,
            message: 'Google authentication failed',
            error: error.message
        });
    }
};