// backend/src/controllers/emailVerificationController.ts - بهینه‌سازی شده با Redis
import { Response } from 'express';
import User from '../../models/users';
import { EmailService } from '../../services/emailService';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { AuthRequest } from '../../middlewares/auth';
import jwt from 'jsonwebtoken';
import { redisClient } from '../../config/redis';

// کلیدهای کش
const CACHE_KEYS = {
    VERIFICATION_CODE: 'verification_code',
    VERIFICATION_ATTEMPTS: 'verification_attempts',
    BLOCKED_VERIFICATION: 'blocked_verification',
    TEMP_TOKENS: 'temp_tokens',
    USER_VERIFICATION_STATUS: 'user_verification_status'
};

// زمان انقضای کش (ثانیه)
const CACHE_TTL = {
    SHORT: 300,      // 5 دقیقه
    MEDIUM: 600,     // 10 دقیقه
    LONG: 1800,      // 30 دقیقه
    VERY_LONG: 3600  // 1 ساعت
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

// تابع برای مدیریت تلاش‌های ناموفق تأیید کد
const handleVerificationAttempt = async (email: string, ip: string): Promise<{ blocked: boolean; remainingAttempts: number }> => {
    const attemptKey = `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:${email}:${ip}`;
    const blockKey = `${CACHE_KEYS.BLOCKED_VERIFICATION}:${email}:${ip}`;

    // بررسی اگر کاربر بلاک شده
    const isBlocked = await redisClient.get(blockKey);
    if (isBlocked) {
        return { blocked: true, remainingAttempts: 0 };
    }

    // افزایش تعداد تلاش‌ها
    const attempts = await redisClient.incr(attemptKey);

    // اگر اولین تلاش است، TTL تنظیم کن
    if (attempts === 1) {
        await redisClient.expire(attemptKey, 900); // 15 دقیقه
    }

    // اگر بیش از 3 تلاش ناموفق، کاربر را بلاک کن
    if (attempts >= 3) {
        await redisClient.setEx(blockKey, 1800, 'blocked'); // 30 دقیقه بلاک
        await redisClient.del(attemptKey);

        logger.warn('User temporarily blocked due to failed verification attempts', {
            email,
            ip,
            attempts
        });

        return { blocked: true, remainingAttempts: 0 };
    }

    return { blocked: false, remainingAttempts: 3 - attempts };
};

// تابع برای ریست کردن تلاش‌های ناموفق
const resetVerificationAttempts = async (email: string, ip: string): Promise<void> => {
    const attemptKey = `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:${email}:${ip}`;
    const blockKey = `${CACHE_KEYS.BLOCKED_VERIFICATION}:${email}:${ip}`;

    await Promise.all([
        redisClient.del(attemptKey),
        redisClient.del(blockKey)
    ]);
};

export const sendVerificationEmail = async (req: AuthRequest, res: Response) => {
    try {
        // اضافه کردن چک برای وجود req.user
        if (!req.user || !req.user.userId) {
            logger.warn('No user found in request for email verification');
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        const userId = req.user.userId;
        const ip = req.ip || 'unknown';

        logger.debug('Sending verification CODE for user', { userId, ip });

        // 🔥 بررسی rate limiting برای ارسال ایمیل
        const emailLimitKey = `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:send:${userId}:${ip}`;
        const emailAttempts = await redisClient.incr(emailLimitKey);

        if (emailAttempts === 1) {
            await redisClient.expire(emailLimitKey, 300); // 5 دقیقه
        }

        if (emailAttempts > 3) {
            logger.warn('Too many verification email requests', { userId, ip, attempts: emailAttempts });
            return res.status(429).json({
                success: false,
                message: 'تعداد درخواست‌های ارسال ایمیل بیش از حد مجاز است. لطفاً 5 دقیقه دیگر تلاش کنید.'
            });
        }

        const user = await User.findById(userId);
        if (!user) {
            logger.warn('User not found for email verification', { userId });
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        logger.debug('User found for email verification', { email: user.email });

        if (user.emailVerified) {
            logger.warn('Email already verified', { userId, email: user.email });
            return res.status(400).json({
                success: false,
                message: 'Email already verified'
            });
        }

        // تولید کد 6 رقمی
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 دقیقه

        logger.debug('Generated 6-digit verification code', {
            userId,
            email: user.email,
            code: verificationCode
        });

        // 🔥 ذخیره کد در Redis
        const codeKey = `${CACHE_KEYS.VERIFICATION_CODE}:${user.email}`;
        await cacheSet(codeKey, {
            code: verificationCode,
            expiresAt: codeExpires.toISOString(),
            attempts: 0,
            createdAt: new Date().toISOString()
        }, 600); // 10 دقیقه

        // آپدیت کاربر با کد تأیید
        await User.findByIdAndUpdate(userId, {
            emailVerificationCode: verificationCode,
            emailVerificationCodeExpires: codeExpires,
            emailVerificationSentAt: new Date()
        });

        // ارسال ایمیل با کد
        const emailSent = await EmailService.sendVerificationCode(
            user.email,
            verificationCode,
            user.name
        );

        logger.debug('Email sending result', { emailSent, userId });

        if (!emailSent) {
            // حذف کد از کش اگر ایمیل ارسال نشد
            await cacheDelete(codeKey);
            logger.error('Failed to send verification email', { userId, email: user.email });
            return res.status(500).json({
                success: false,
                message: 'Failed to send verification email'
            });
        }

        LoggerService.authLog(userId, 'verification_code_sent', {
            email: user.email,
            code: verificationCode
        });

        logger.info('Verification code sent successfully', {
            userId,
            email: user.email
        });

        res.json({
            success: true,
            message: 'Verification code sent successfully'
        });

    } catch (error: any) {
        logger.error('Send verification error', {
            error: error.message,
            stack: error.stack,
            userId: req.user?.userId
        });
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};

export const verifyEmailCode = async (req: AuthRequest, res: Response) => {
    try {
        const { code, email } = req.body;
        const ip = req.ip || 'unknown';

        logger.debug('Verifying email code', { email, codeLength: code?.length, ip });

        if (!code || code.length !== 6) {
            logger.warn('Invalid verification code format', { codeLength: code?.length });
            return res.status(400).json({
                success: false,
                message: 'Valid 6-digit verification code is required'
            });
        }

        if (!email) {
            logger.warn('Email missing for verification');
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        // 🔥 بررسی rate limiting برای تأیید کد
        const verificationCheck = await handleVerificationAttempt(email, ip);
        if (verificationCheck.blocked) {
            return res.status(429).json({
                success: false,
                message: 'تعداد تلاش‌های ناموفق بیش از حد مجاز است. لطفاً 30 دقیقه دیگر تلاش کنید.'
            });
        }

        // 🔥 اول بررسی کش برای کد تأیید
        const codeKey = `${CACHE_KEYS.VERIFICATION_CODE}:${email}`;
        const cachedCode = await cacheGet(codeKey);

        if (cachedCode) {
            // بررسی انقضای کد در کش
            const expiresAt = new Date(cachedCode.expiresAt);
            if (expiresAt < new Date()) {
                await cacheDelete(codeKey);
                logger.warn('Cached verification code expired', { email });
                return res.status(400).json({
                    success: false,
                    message: 'Verification code has expired'
                });
            }

            // بررسی تطابق کد
            if (cachedCode.code === code) {
                // کد صحیح است
                await handleSuccessfulVerification(email, ip, cachedCode);
                return res.json(await generateVerificationResponse(email));
            } else {
                // کد ناصحیح
                await handleFailedVerificationAttempt(email, ip, cachedCode, codeKey);
                return res.status(400).json({
                    success: false,
                    message: 'Invalid verification code',
                    remainingAttempts: verificationCheck.remainingAttempts - 1
                });
            }
        }

        // اگر در کش نبود، از دیتابیس بررسی کن
        const user = await User.findOne({
            email: email.toLowerCase(),
            emailVerificationCode: code,
            emailVerificationCodeExpires: { $gt: new Date() }
        });

        if (!user) {
            // افزایش شمارنده تلاش‌های ناموفق
            await handleVerificationAttempt(email, ip);

            // دیباگ بیشتر
            const userForDebug = await User.findOne({ email: email.toLowerCase() });
            logger.warn('Invalid or expired verification code', {
                email,
                storedCode: userForDebug?.emailVerificationCode,
                enteredCode: code,
                codeMatches: userForDebug?.emailVerificationCode === code,
                codeExpired: userForDebug?.emailVerificationCodeExpires! < new Date(),
                hasCode: !!userForDebug?.emailVerificationCode
            });

            return res.status(400).json({
                success: false,
                message: 'Invalid or expired verification code',
                remainingAttempts: verificationCheck.remainingAttempts - 1
            });
        }

        // کد معتبر است
        await handleSuccessfulVerification(email, ip, {
            code,
            userId: user._id.toString()
        });

        res.json(await generateVerificationResponse(email, user._id.toString()));

    } catch (error: any) {
        logger.error('Verify email code error', {
            error: error.message,
            stack: error.stack,
            email: req.body.email
        });
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};

// تابع کمکی برای پردازش تأیید موفق
const handleSuccessfulVerification = async (email: string, ip: string, codeData: any) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return;

        // تأیید ایمیل در دیتابیس
        await User.findByIdAndUpdate(user._id, {
            emailVerified: true,
            emailVerificationCode: undefined,
            emailVerificationCodeExpires: undefined
        });

        // 🔥 حذف کد از کش
        const codeKey = `${CACHE_KEYS.VERIFICATION_CODE}:${email}`;
        await cacheDelete(codeKey);

        // 🔥 ریست کردن تلاش‌های ناموفق
        await resetVerificationAttempts(email, ip);

        // 🔥 آپدیت وضعیت تأیید در کش
        const statusKey = `${CACHE_KEYS.USER_VERIFICATION_STATUS}:${user._id.toString()}`;
        await cacheSet(statusKey, {
            verified: true,
            verifiedAt: new Date().toISOString()
        }, CACHE_TTL.VERY_LONG);

        // 🔥 حذف کش کاربر برای آپدیت اطلاعات
        const userCacheKey = `user_profile:${email}`;
        await cacheDelete(userCacheKey);

        // ارسال ایمیل خوش‌آمدگویی
        await EmailService.sendWelcomeEmail(user.email, user.name);

        LoggerService.authLog(user._id.toString(), 'email_verified', {
            email: user.email
        });

        logger.info('Email verified successfully', {
            userId: user._id.toString(),
            email: user.email
        });

    } catch (error) {
        logger.error('Error in handleSuccessfulVerification', { email, error });
    }
};

// تابع کمکی برای پردازش تلاش ناموفق
const handleFailedVerificationAttempt = async (email: string, ip: string, cachedCode: any, codeKey: string) => {
    try {
        // افزایش شمارنده تلاش‌ها در کش
        cachedCode.attempts = (cachedCode.attempts || 0) + 1;

        // اگر بیش از 3 بار تلاش ناموفق، کد را حذف کن
        if (cachedCode.attempts >= 3) {
            await cacheDelete(codeKey);

            // آپدیت دیتابیس برای حذف کد
            await User.findOneAndUpdate(
                { email: email.toLowerCase() },
                {
                    emailVerificationCode: undefined,
                    emailVerificationCodeExpires: undefined
                }
            );

            logger.warn('Verification code invalidated due to multiple failed attempts', { email });
        } else {
            // آپدیت کش با شمارنده جدید
            await cacheSet(codeKey, cachedCode, 600);
        }

        // افزایش شمارنده تلاش‌های ناموفق
        await handleVerificationAttempt(email, ip);

    } catch (error) {
        logger.error('Error in handleFailedVerificationAttempt', { email, error });
    }
};

// تابع کمکی برای تولید پاسخ تأیید
const generateVerificationResponse = async (email: string, userId?: string) => {
    let user = null;

    if (userId) {
        user = await User.findById(userId);
    } else {
        user = await User.findOne({ email: email.toLowerCase() });
    }

    if (!user) {
        throw new Error('User not found');
    }

    // تولید توکن اصلی
    const token = jwt.sign(
        { userId: user._id.toString() },
        process.env.JWT_SECRET!,
        { expiresIn: '120d' }
    );

    // 🔥 ذخیره توکن در کش
    const tokenKey = `${CACHE_KEYS.TEMP_TOKENS}:${user._id.toString()}`;
    await cacheSet(tokenKey, {
        token: token,
        type: 'access_token',
        createdAt: new Date().toISOString()
    }, CACHE_TTL.VERY_LONG);

    return {
        success: true,
        message: 'Email verified successfully',
        token,
        user: {
            id: user._id.toString(),
            name: user.name,
            email: user.email,
            emailVerified: true
        }
    };
};

export const resendVerification = async (req: AuthRequest, res: Response) => {
    try {
        const { email } = req.body;
        const ip = req.ip || 'unknown';

        if (!email) {
            logger.warn('Resend verification - email missing');
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        // 🔥 بررسی rate limiting برای ارسال مجدد
        const resendLimitKey = `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:resend:${email}:${ip}`;
        const resendAttempts = await redisClient.incr(resendLimitKey);

        if (resendAttempts === 1) {
            await redisClient.expire(resendLimitKey, 300); // 5 دقیقه
        }

        if (resendAttempts > 2) {
            logger.warn('Too many resend verification requests', { email, ip, attempts: resendAttempts });
            return res.status(429).json({
                success: false,
                message: 'تعداد درخواست‌های ارسال مجدد کد بیش از حد مجاز است. لطفاً 5 دقیقه دیگر تلاش کنید.'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            logger.warn('Resend verification - user not found', { email });
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.emailVerified) {
            logger.warn('Resend verification - email already verified', { email });
            return res.status(400).json({
                success: false,
                message: 'Email already verified'
            });
        }

        // بررسی rate limiting در دیتابیس
        const lastSent = user.emailVerificationSentAt;
        if (lastSent && Date.now() - lastSent.getTime() < 2 * 60 * 1000) { // 2 دقیقه
            logger.warn('Resend verification - too frequent', {
                email,
                lastSent: lastSent.toISOString()
            });
            return res.status(429).json({
                success: false,
                message: 'Please wait before requesting another verification code'
            });
        }

        // تولید کد جدید
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const codeExpires = new Date(Date.now() + 10 * 60 * 1000);

        // 🔥 ذخیره کد جدید در کش
        const codeKey = `${CACHE_KEYS.VERIFICATION_CODE}:${email}`;
        await cacheSet(codeKey, {
            code: verificationCode,
            expiresAt: codeExpires.toISOString(),
            attempts: 0,
            createdAt: new Date().toISOString()
        }, 600);

        // آپدیت کاربر
        await User.findByIdAndUpdate(user._id, {
            emailVerificationCode: verificationCode,
            emailVerificationCodeExpires: codeExpires,
            emailVerificationSentAt: new Date()
        });

        // ارسال ایمیل
        const emailSent = await EmailService.sendVerificationCode(
            user.email,
            verificationCode,
            user.name
        );

        if (!emailSent) {
            // حذف کد از کش اگر ایمیل ارسال نشد
            await cacheDelete(codeKey);
            logger.error('Resend verification - failed to send email', { email });
            return res.status(500).json({
                success: false,
                message: 'Failed to send verification email'
            });
        }

        LoggerService.authLog(user._id.toString(), 'verification_code_resent', {
            email: user.email
        });

        logger.info('Verification code resent successfully', {
            userId: user._id.toString(),
            email: user.email
        });

        res.json({
            success: true,
            message: 'Verification code sent successfully'
        });

    } catch (error: any) {
        logger.error('Resend verification code error', {
            error: error.message,
            stack: error.stack,
            email: req.body.email
        });
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};

// 🆕 تابع برای بررسی وضعیت تأیید ایمیل از کش
export const getVerificationStatus = async (userId: string): Promise<{ verified: boolean; verifiedAt?: string }> => {
    try {
        const statusKey = `${CACHE_KEYS.USER_VERIFICATION_STATUS}:${userId}`;
        const cachedStatus = await cacheGet(statusKey);

        if (cachedStatus) {
            return cachedStatus;
        }

        // اگر در کش نبود، از دیتابیس بگیر
        const user = await User.findById(userId).select('emailVerified emailVerificationSentAt');
        if (!user) {
            return { verified: false };
        }

        const status = {
            verified: user.emailVerified,
            verifiedAt: user.emailVerified ? user.emailVerificationSentAt?.toISOString() : undefined
        };

        // ذخیره در کش
        await cacheSet(statusKey, status, CACHE_TTL.LONG);

        return status;
    } catch (error) {
        logger.error('Error getting verification status', { userId, error });
        return { verified: false };
    }
};

// 🆕 تابع برای حذف تمام کش‌های مربوط به تأیید ایمیل
export const invalidateVerificationCache = async (email: string, userId?: string): Promise<void> => {
    try {
        const keysToDelete = [];

        if (email) {
            keysToDelete.push(
                `${CACHE_KEYS.VERIFICATION_CODE}:${email}`,
                `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:${email}:*`,
                `${CACHE_KEYS.BLOCKED_VERIFICATION}:${email}:*`,
                `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:send:*:${email}`,
                `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:resend:${email}:*`
            );
        }

        if (userId) {
            keysToDelete.push(
                `${CACHE_KEYS.USER_VERIFICATION_STATUS}:${userId}`,
                `${CACHE_KEYS.TEMP_TOKENS}:${userId}`
            );
        }

        // حذف کلیدهای pattern-based
        for (const pattern of keysToDelete.filter(k => k.includes('*'))) {
            const matchingKeys = await redisClient.keys(pattern);
            if (matchingKeys.length > 0) {
                await redisClient.del(matchingKeys);
            }
        }

        // حذف کلیدهای مستقیم
        const directKeys = keysToDelete.filter(k => !k.includes('*'));
        if (directKeys.length > 0) {
            await redisClient.del(directKeys);
        }

        logger.debug('Verification cache invalidated', { email, userId });

    } catch (error) {
        logger.error('Error invalidating verification cache', { email, userId, error });
    }
};