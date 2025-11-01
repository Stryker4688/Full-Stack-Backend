// backend/src/controllers/emailVerificationController.ts
import { Response } from 'express';
import User from '../../models/users';
import { EmailService } from '../../services/emailService';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { AuthRequest } from '../../middlewares/auth';
import jwt from 'jsonwebtoken';

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

        logger.debug('Sending verification CODE for user', { userId });

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

        logger.debug('Verifying email code', { email, codeLength: code?.length });

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

        // پیدا کردن کاربر با ایمیل و کد معتبر
        const user = await User.findOne({
            email: email.toLowerCase(),
            emailVerificationCode: code,
            emailVerificationCodeExpires: { $gt: new Date() }
        });

        if (!user) {
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
                message: 'Invalid or expired verification code'
            });
        }

        // تأیید ایمیل
        await User.findByIdAndUpdate(user._id, {
            emailVerified: true,
            emailVerificationCode: undefined,
            emailVerificationCodeExpires: undefined
        });

        // تولید توکن اصلی
        const token = jwt.sign(
            { userId: user._id.toString() },
            process.env.JWT_SECRET!,
            { expiresIn: '120d' }
        );

        // ارسال ایمیل خوش‌آمدگویی
        await EmailService.sendWelcomeEmail(user.email, user.name);

        LoggerService.authLog(user._id.toString(), 'email_verified', {
            email: user.email
        });

        logger.info('Email verified successfully', {
            userId: user._id.toString(),
            email: user.email
        });

        res.json({
            success: true,
            message: 'Email verified successfully',
            token,
            user: {
                id: user._id.toString(),
                name: user.name,
                email: user.email,
                emailVerified: true
            }
        });

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

export const resendVerification = async (req: AuthRequest, res: Response) => {
    try {
        const { email } = req.body;

        if (!email) {
            logger.warn('Resend verification - email missing');
            return res.status(400).json({
                success: false,
                message: 'Email is required'
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

        // بررسی rate limiting
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