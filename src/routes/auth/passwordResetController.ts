// backend/src/controllers/passwordResetController.ts - Optimized with Redis
import { Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import User from '../../models/users';
import { EmailService } from '../../services/emailService';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { AuthRequest } from '../../middlewares/auth';
import { cacheWithFallback, generateKey, CACHE_TTL, clearUserCache } from '../../utils/cacheUtils';

export const forgotPassword = async (req: AuthRequest, res: Response) => {
    try {
        const { email } = req.body;

        if (!email) {
            logger.warn('Forgot password - email missing');
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        logger.debug('Forgot password request', { email });

        // Find user with cache
        const user = await cacheWithFallback(
            generateKey.userProfile(`email:${email}`),
            async () => await User.findOne({ email: email.toLowerCase() }),
            CACHE_TTL.SHORT
        );

        // For security, return same message even if user doesn't exist
        if (!user) {
            logger.debug('Forgot password - user not found (but returning success for security)');
            return res.json({
                success: true,
                message: 'If the email exists, a verification code has been sent'
            });
        }

        // Check rate limiting
        const lastResetRequest = user.emailVerificationSentAt;
        if (lastResetRequest && Date.now() - lastResetRequest.getTime() < 2 * 60 * 1000) {
            logger.warn('Forgot password - too frequent requests', {
                email,
                lastRequest: lastResetRequest.toISOString()
            });
            return res.status(429).json({
                success: false,
                message: 'Please wait before requesting another password reset'
            });
        }

        // Generate 6-digit code
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

        // Save code to database
        await User.findByIdAndUpdate(user._id, {
            emailVerificationCode: resetCode,
            emailVerificationCodeExpires: new Date(Date.now() + 10 * 60 * 1000),
            emailVerificationSentAt: new Date()
        });

        // Clear user cache
        await clearUserCache(user._id.toString());

        // Send email with code
        const emailSent = await EmailService.sendPasswordResetCode(
            user.email,
            resetCode,
            user.name
        );

        if (!emailSent) {
            logger.error('Failed to send password reset code', { email });
            return res.status(500).json({
                success: false,
                message: 'Failed to send verification code'
            });
        }

        LoggerService.authLog(user._id.toString(), 'password_reset_code_sent', {
            email: user.email
        });

        logger.info('Password reset code sent successfully', {
            userId: user._id.toString(),
            email: user.email
        });

        res.json({
            success: true,
            message: 'If the email exists, a verification code has been sent'
        });

    } catch (error: any) {
        logger.error('Forgot password error', {
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

export const verifyResetCode = async (req: AuthRequest, res: Response) => {
    try {
        const { code, email } = req.body;

        if (!code || !email) {
            logger.warn('Verify reset code - missing code or email');
            return res.status(400).json({
                success: false,
                message: 'Code and email are required'
            });
        }

        logger.debug('Verify reset code attempt', { email, code });

        // Find user with valid code - no cache for security
        const user = await User.findOne({
            email: email.toLowerCase(),
            emailVerificationCode: code,
            emailVerificationCodeExpires: { $gt: new Date() }
        });

        if (!user) {
            logger.warn('Verify reset code - invalid or expired code', { email });
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired verification code'
            });
        }

        // Generate token for password reset
        const resetToken = jwt.sign(
            {
                userId: user._id.toString(),
                type: 'password_reset',
                email: user.email,
                codeVerified: true
            },
            process.env.JWT_SECRET!,
            { expiresIn: '30m' }
        );

        LoggerService.authLog(user._id.toString(), 'reset_code_verified', {
            email: user.email
        });

        logger.info('Reset code verified successfully', {
            userId: user._id.toString(),
            email: user.email
        });

        res.json({
            success: true,
            message: 'Code verified successfully',
            resetToken: resetToken
        });

    } catch (error: any) {
        logger.error('Verify reset code error', {
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

export const resetPassword = async (req: AuthRequest, res: Response) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            logger.warn('Reset password - missing token or new password');
            return res.status(400).json({
                success: false,
                message: 'Token and new password are required'
            });
        }

        if (newPassword.length < 6) {
            logger.warn('Reset password - password too short');
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long'
            });
        }

        logger.debug('Reset password attempt');

        // Verify token
        let decoded: any;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET!);
        } catch (error) {
            logger.warn('Reset password - invalid or expired token');
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }

        if (decoded.type !== 'password_reset' || !decoded.codeVerified) {
            logger.warn('Reset password - invalid token type', { type: decoded.type });
            return res.status(401).json({
                success: false,
                message: 'Invalid token type'
            });
        }

        // Find user
        const user = await User.findById(decoded.userId);

        if (!user) {
            logger.warn('Reset password - user not found', {
                userId: decoded.userId
            });
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        // Hash new password
        const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
            .update(newPassword)
            .digest('hex');
        const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

        // Update user and clear code
        await User.findByIdAndUpdate(user._id, {
            password: hashedPassword,
            emailVerificationCode: undefined,
            emailVerificationCodeExpires: undefined,
            emailVerificationSentAt: undefined,
            lastLogin: new Date()
        });

        // Clear user cache
        await clearUserCache(user._id.toString());

        // Send confirmation email
        await EmailService.sendPasswordChangedConfirmation(user.email, user.name);

        LoggerService.authLog(user._id.toString(), 'password_reset_success', {
            email: user.email
        });

        logger.info('Password reset successfully', {
            userId: user._id.toString(),
            email: user.email
        });

        res.json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error: any) {
        logger.error('Reset password error', {
            error: error.message,
            stack: error.stack
        });
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};