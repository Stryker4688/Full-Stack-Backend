// backend/src/controllers/googleAuthController.ts - بهینه‌سازی شده با Redis
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import User from '../../models/users';
import { GoogleAuthService } from '../../services/googleAuthService';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { AuthRequest } from '../../middlewares/auth';
import { redisClient } from '../../config/redis';

// کلیدهای کش
const CACHE_KEYS = {
    GOOGLE_USER: 'google_user',
    GOOGLE_TOKENS: 'google_tokens',
    AUTH_SESSIONS: 'auth_sessions',
    TEMP_TOKENS: 'temp_tokens',
    GOOGLE_RATE_LIMIT: 'google_rate_limit'
};

// زمان انقضای کش (ثانیه)
const CACHE_TTL = {
    SHORT: 300,      // 5 دقیقه
    MEDIUM: 1800,    // 30 دقیقه
    LONG: 3600,      // 1 ساعت
    VERY_LONG: 86400 // 24 ساعت
};

// توابع کمکی کش
const cacheGet = async (key: string): Promise<any> => {
    try {
        const cached = await redisClient.get(key);
        return cached ? JSON.parse(cached) : null;
    } catch (error) {
        logger.error('Cache get error', { key, error });
        return null;
    }
};

const cacheSet = async (key: string, data: any, ttl: number = CACHE_TTL.MEDIUM): Promise<void> => {
    try {
        await redisClient.setEx(key, ttl, JSON.stringify(data));
    } catch (error) {
        logger.error('Cache set error', { key, error });
    }
};

const cacheDelete = async (key: string): Promise<void> => {
    try {
        await redisClient.del(key);
    } catch (error) {
        logger.error('Cache delete error', { key, error });
    }
};

// تابع برای مدیریت rate limiting
const checkRateLimit = async (identifier: string, maxAttempts: number = 10, windowMs: number = 300): Promise<{ allowed: boolean; remaining: number }> => {
    const rateLimitKey = `${CACHE_KEYS.GOOGLE_RATE_LIMIT}:${identifier}`;

    try {
        const current = await redisClient.incr(rateLimitKey);

        if (current === 1) {
            await redisClient.expire(rateLimitKey, windowMs);
        }

        const remaining = Math.max(0, maxAttempts - current);
        const allowed = current <= maxAttempts;

        return { allowed, remaining };
    } catch (error) {
        logger.error('Rate limit check error', { identifier, error });
        return { allowed: true, remaining: maxAttempts }; // Fail open
    }
};

export const googleAuth = async (req: AuthRequest, res: Response) => {
    try {
        const { code, idToken, rememberMe = false } = req.body;
        const ip = req.ip || 'unknown';

        logger.debug('Google auth attempt', {
            hasCode: !!code,
            hasToken: !!idToken,
            ip
        });

        // 🔥 بررسی rate limiting
        const rateLimitCheck = await checkRateLimit(ip, 15, 300); // 15 درخواست در 5 دقیقه
        if (!rateLimitCheck.allowed) {
            logger.warn('Google auth rate limit exceeded', { ip, remaining: rateLimitCheck.remaining });
            return res.status(429).json({
                success: false,
                message: 'تعداد درخواست‌های احراز هویت بیش از حد مجاز است. لطفاً چند دقیقه دیگر تلاش کنید.'
            });
        }

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

            // 🔥 بررسی کش برای code
            const codeCacheKey = `${CACHE_KEYS.GOOGLE_TOKENS}:code:${code}`;
            const cachedToken = await cacheGet(codeCacheKey);

            if (cachedToken) {
                usedIdToken = cachedToken.idToken;
                googleUser = cachedToken.userInfo;
                logger.debug('Using cached Google token from code', { code });
            } else {
                try {
                    usedIdToken = await GoogleAuthService.getTokenFromCode(code);
                    googleUser = await GoogleAuthService.verifyToken(usedIdToken);

                    // 🔥 ذخیره در کش
                    await cacheSet(codeCacheKey, {
                        idToken: usedIdToken,
                        userInfo: googleUser
                    }, CACHE_TTL.SHORT);

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
        }
        // ۳. اگر مستقیم idToken داریم
        else if (idToken) {
            logger.debug('Processing direct token flow');

            // 🔥 بررسی کش برای token
            const tokenCacheKey = `${CACHE_KEYS.GOOGLE_TOKENS}:token:${idToken}`;
            const cachedUser = await cacheGet(tokenCacheKey);

            if (cachedUser) {
                usedIdToken = idToken;
                googleUser = cachedUser;
                logger.debug('Using cached Google user from token', { token: idToken.substring(0, 20) + '...' });
            } else {
                usedIdToken = idToken;
                googleUser = await GoogleAuthService.verifyToken(idToken);

                // 🔥 ذخیره در کش
                await cacheSet(tokenCacheKey, googleUser, CACHE_TTL.MEDIUM);
            }
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
        // 🔥 اول بررسی کش
        const userByEmailKey = `${CACHE_KEYS.GOOGLE_USER}:email:${googleUser.email}`;
        const userByGoogleIdKey = `${CACHE_KEYS.GOOGLE_USER}:google:${googleUser.googleId}`;

        let user = await cacheGet(userByEmailKey) || await cacheGet(userByGoogleIdKey);

        if (!user) {
            // اگر در کش نیست، از دیتابیس بگیر
            user = await User.findOne({
                $or: [
                    { googleId: googleUser.googleId },
                    { email: googleUser.email.toLowerCase() }
                ]
            });

            if (user) {
                // 🔥 ذخیره در کش
                await Promise.all([
                    cacheSet(userByEmailKey, user, CACHE_TTL.MEDIUM),
                    cacheSet(userByGoogleIdKey, user, CACHE_TTL.MEDIUM)
                ]);
            }
        }

        let requiresPasswordSetup = false;
        let tempToken = '';

        if (!user) {
            // 🆕 کاربر جدید - نیاز به تنظیم رمز عبور دارد
            logger.debug('New Google user - requiring password setup', {
                email: googleUser.email
            });

            // 🔥 ذخیره اطلاعات کاربر گوگل در کش
            const tempUserKey = `${CACHE_KEYS.TEMP_TOKENS}:google:${googleUser.googleId}`;
            await cacheSet(tempUserKey, {
                googleUser: {
                    googleId: googleUser.googleId,
                    email: googleUser.email.toLowerCase(),
                    name: googleUser.name || googleUser.email.split('@')[0],
                    picture: googleUser.picture,
                    emailVerified: googleUser.emailVerified || false
                },
                type: 'google_password_setup',
                createdAt: new Date().toISOString()
            }, CACHE_TTL.MEDIUM);

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
                { expiresIn: '1h' }
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

            // 🔥 آپدیت کش
            await Promise.all([
                cacheSet(userByEmailKey, user, CACHE_TTL.MEDIUM),
                cacheSet(userByGoogleIdKey, user, CACHE_TTL.MEDIUM)
            ]);

            // اگر کاربر رمز عبور ندارد (کاربر قدیمی گوگل)، نیاز به تنظیم رمز عبور دارد
            if (!user.password) {
                // 🔥 ذخیره در کش برای تنظیم رمز عبور
                const tempSetupKey = `${CACHE_KEYS.TEMP_TOKENS}:password_setup:${user._id.toString()}`;
                await cacheSet(tempSetupKey, {
                    userId: user._id.toString(),
                    type: 'google_password_setup',
                    createdAt: new Date().toISOString()
                }, CACHE_TTL.MEDIUM);

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

        // 🔥 ذخیره session در Redis
        const sessionKey = `${CACHE_KEYS.AUTH_SESSIONS}:${user!._id.toString()}`;
        await cacheSet(sessionKey, {
            userId: user!._id.toString(),
            provider: 'google',
            loginTime: new Date().toISOString(),
            expiresIn
        }, rememberMe ? CACHE_TTL.VERY_LONG : CACHE_TTL.LONG);

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

// 🆕 تابع برای دریافت اطلاعات session از کش
export const getGoogleAuthSession = async (userId: string): Promise<any> => {
    try {
        const sessionKey = `${CACHE_KEYS.AUTH_SESSIONS}:${userId}`;
        return await cacheGet(sessionKey);
    } catch (error) {
        logger.error('Error getting Google auth session', { userId, error });
        return null;
    }
};

// 🆕 تابع برای حذف session از کش
export const clearGoogleAuthSession = async (userId: string): Promise<void> => {
    try {
        const sessionKey = `${CACHE_KEYS.AUTH_SESSIONS}:${userId}`;
        await cacheDelete(sessionKey);

        // حذف اطلاعات کاربر از کش
        const userKeys = await redisClient.keys(`${CACHE_KEYS.GOOGLE_USER}:*:${userId}`);
        if (userKeys.length > 0) {
            await redisClient.del(userKeys);
        }

        logger.debug('Google auth session cleared', { userId });
    } catch (error) {
        logger.error('Error clearing Google auth session', { userId, error });
    }
};

// 🆕 تابع برای بررسی وجود کاربر گوگل از کش
export const getCachedGoogleUser = async (email: string, googleId: string): Promise<any> => {
    try {
        const userByEmail = await cacheGet(`${CACHE_KEYS.GOOGLE_USER}:email:${email}`);
        if (userByEmail) return userByEmail;

        const userByGoogleId = await cacheGet(`${CACHE_KEYS.GOOGLE_USER}:google:${googleId}`);
        if (userByGoogleId) return userByGoogleId;

        return null;
    } catch (error) {
        logger.error('Error getting cached Google user', { email, googleId, error });
        return null;
    }
};

// 🆕 تابع برای حذف کاربر گوگل از کش
export const invalidateGoogleUserCache = async (email: string, googleId: string, userId?: string): Promise<void> => {
    try {
        const keysToDelete = [
            `${CACHE_KEYS.GOOGLE_USER}:email:${email}`,
            `${CACHE_KEYS.GOOGLE_USER}:google:${googleId}`,
            `${CACHE_KEYS.AUTH_SESSIONS}:${userId}`,
            `${CACHE_KEYS.TEMP_TOKENS}:google:${googleId}`,
            `${CACHE_KEYS.TEMP_TOKENS}:password_setup:${userId}`
        ].filter(Boolean);

        await Promise.all(keysToDelete.map(key => cacheDelete(key)));

        logger.debug('Google user cache invalidated', { email, googleId, userId });
    } catch (error) {
        logger.error('Error invalidating Google user cache', { email, googleId, userId, error });
    }
};