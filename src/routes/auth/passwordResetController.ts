// backend/src/controllers/passwordResetController.ts - Optimized with cache utilities
import { Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import User from '../../models/users';
import { EmailService } from '../../services/emailService';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { AuthRequest } from '../../middlewares/auth';
import {
    cacheGet,
    cacheSet,
    cacheDelete,
    cacheIncr,
    clearUserCache,
    clearAuthCache,
    generateKey,
    CACHE_TTL
} from '../../utils/cacheUtils';
import { redisClient } from '../../config/redis';

// Manage password reset attempts and blocking
const handleResetAttempt = async (email: string, ip: string): Promise<{ blocked: boolean; remainingAttempts: number }> => {
    const attemptKey = generateKey.rateLimit(`password_reset:${email}:${ip}`);
    const blockKey = generateKey.rateLimit(`blocked_password_reset:${email}:${ip}`);

    // Check if user is blocked
    const isBlocked = await cacheGet(blockKey);
    if (isBlocked) {
        return { blocked: true, remainingAttempts: 0 };
    }

    // Increment attempt counter
    const attempts = await cacheIncr(attemptKey, 900); // 15 minutes TTL

    // Block if exceeded maximum attempts
    if (attempts >= 5) {
        await cacheSet(blockKey, 'blocked', 1800); // 30 minutes block
        await cacheDelete(attemptKey);

        logger.warn('User temporarily blocked due to failed password reset attempts', {
            email,
            ip,
            attempts
        });

        return { blocked: true, remainingAttempts: 0 };
    }

    return { blocked: false, remainingAttempts: 5 - attempts };
};

// Reset password reset attempts
const resetResetAttempts = async (email: string, ip: string): Promise<void> => {
    const attemptKey = generateKey.rateLimit(`password_reset:${email}:${ip}`);
    const blockKey = generateKey.rateLimit(`blocked_password_reset:${email}:${ip}`);

    await Promise.all([
        cacheDelete(attemptKey),
        cacheDelete(blockKey)
    ]);
};

export const requestPasswordReset = async (req: AuthRequest, res: Response) => {
    try {
        const { email } = req.body;
        const ip = req.ip || 'unknown';

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email address is required'
            });
        }

        logger.debug('Password reset request received', { email, ip });

        // Check rate limiting
        const resetCheck = await handleResetAttempt(email, ip);
        if (resetCheck.blocked) {
            return res.status(429).json({
                success: false,
                message: 'Too many password reset requests. Please wait 30 minutes before trying again.'
            });
        }

        // Find user by email
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            // For security, return success even if user doesn't exist
            logger.warn('Password reset requested for non-existent email', { email });
            return res.json({
                success: true,
                message: 'If the email exists, a reset code has been sent to your email'
            });
        }

        // Check if user uses Google authentication without password
        if (user.authProvider === 'google' && !user.password) {
            return res.status(400).json({
                success: false,
                message: 'This account uses Google authentication. Please use Google to sign in.'
            });
        }

        // Generate 6-digit reset code
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Store reset code in cache
        const codeKey = generateKey.passwordResetCode(email);
        await cacheSet(codeKey, {
            code: resetCode,
            expiresAt: codeExpires.toISOString(),
            attempts: 0,
            createdAt: new Date().toISOString(),
            userId: user._id.toString()
        }, 600); // 10 minutes TTL

        // Send password reset email
        const emailSent = await EmailService.sendPasswordResetCode(
            user.email,
            resetCode,
            user.name
        );

        if (!emailSent) {
            await cacheDelete(codeKey);
            return res.status(500).json({
                success: false,
                message: 'Failed to send password reset code email'
            });
        }

        LoggerService.authLog(user._id.toString(), 'password_reset_requested', {
            email: user.email
        });

        logger.info('Password reset code sent successfully', {
            userId: user._id.toString(),
            email: user.email
        });

        res.json({
            success: true,
            message: 'If the email exists, a password reset code has been sent to your email'
        });

    } catch (error: any) {
        logger.error('Password reset request process failed', {
            error: error.message,
            stack: error.stack,
            email: req.body.email
        });
        res.status(500).json({
            success: false,
            message: 'Server error during password reset request'
        });
    }
};

export const verifyResetCode = async (req: AuthRequest, res: Response) => {
    try {
        const { email, code } = req.body;
        const ip = req.ip || 'unknown';

        if (!email || !code) {
            return res.status(400).json({
                success: false,
                message: 'Email and reset code are required'
            });
        }

        if (code.length !== 6) {
            return res.status(400).json({
                success: false,
                message: 'Valid 6-digit reset code is required'
            });
        }

        logger.debug('Verifying password reset code', { email, codeLength: code.length, ip });

        // Check rate limiting
        const resetCheck = await handleResetAttempt(email, ip);
        if (resetCheck.blocked) {
            return res.status(429).json({
                success: false,
                message: 'Too many failed verification attempts. Please wait 30 minutes before trying again.'
            });
        }

        // Check cache for reset code
        const codeKey = generateKey.passwordResetCode(email);
        const cachedCode = await cacheGet(codeKey);

        if (!cachedCode) {
            await handleResetAttempt(email, ip);
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset code'
            });
        }

        // Check code expiration
        const expiresAt = new Date(cachedCode.expiresAt);
        if (expiresAt < new Date()) {
            await cacheDelete(codeKey);
            await handleResetAttempt(email, ip);
            return res.status(400).json({
                success: false,
                message: 'Reset code has expired. Please request a new one.'
            });
        }

        // Verify code matches
        if (cachedCode.code !== code) {
            // Increment failed attempts in cache
            cachedCode.attempts = (cachedCode.attempts || 0) + 1;

            // Invalidate code after too many failed attempts
            if (cachedCode.attempts >= 3) {
                await cacheDelete(codeKey);
                logger.warn('Reset code invalidated due to multiple failed attempts', { email });
            } else {
                await cacheSet(codeKey, cachedCode, 600);
            }

            await handleResetAttempt(email, ip);

            return res.status(400).json({
                success: false,
                message: 'Invalid reset code',
                remainingAttempts: resetCheck.remainingAttempts - 1
            });
        }

        // Code is valid - get user information
        const user = await User.findById(cachedCode.userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Generate password reset token
        const resetToken = jwt.sign(
            {
                userId: user._id.toString(),
                email: user.email,
                type: 'password_reset',
                temp: true
            },
            process.env.JWT_SECRET!,
            { expiresIn: '15m' } // 15 minutes
        );

        // Cache reset token
        const tokenKey = `password_reset_tokens:${user._id.toString()}`;
        await cacheSet(tokenKey, {
            token: resetToken,
            email: user.email,
            createdAt: new Date().toISOString()
        }, 900); // 15 minutes TTL

        // Remove used reset code from cache
        await cacheDelete(codeKey);

        // Reset failed attempts
        await resetResetAttempts(email, ip);

        LoggerService.authLog(user._id.toString(), 'password_reset_code_verified', {
            email: user.email
        });

        logger.info('Password reset code verified successfully', {
            userId: user._id.toString(),
            email: user.email
        });

        res.json({
            success: true,
            message: 'Reset code verified successfully',
            resetToken,
            user: {
                id: user._id.toString(),
                name: user.name,
                email: user.email
            }
        });

    } catch (error: any) {
        logger.error('Password reset code verification failed', {
            error: error.message,
            stack: error.stack,
            email: req.body.email
        });
        res.status(500).json({
            success: false,
            message: 'Server error during reset code verification'
        });
    }
};

export const resetPassword = async (req: AuthRequest, res: Response) => {
    try {
        const { resetToken, newPassword } = req.body;

        if (!resetToken || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Reset token and new password are required'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long'
            });
        }

        logger.debug('Processing password reset', { hasToken: !!resetToken, passwordLength: newPassword.length });

        // Verify reset token
        let decoded: any;
        try {
            decoded = jwt.verify(resetToken, process.env.JWT_SECRET!);
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }

        if (decoded.type !== 'password_reset') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token type'
            });
        }

        // Check token in cache
        const tokenKey = `password_reset_tokens:${decoded.userId}`;
        const cachedToken = await cacheGet(tokenKey);

        if (!cachedToken || cachedToken.token !== resetToken) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or already used reset token'
            });
        }

        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Hash new password with pepper
        const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
            .update(newPassword)
            .digest('hex');
        const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

        // Update user password
        user.password = hashedPassword;
        user.lastLogin = new Date();
        await user.save();

        // Remove used reset token from cache
        await cacheDelete(tokenKey);

        // Clear user cache to force refresh
        await clearUserCache(user._id.toString());

        // Send password change confirmation email
        await EmailService.sendPasswordChangedConfirmation(user.email, user.name);

        LoggerService.authLog(user._id.toString(), 'password_reset_successful', {
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
        logger.error('Password reset process failed', {
            error: error.message,
            stack: error.stack
        });
        res.status(500).json({
            success: false,
            message: 'Server error during password reset'
        });
    }
};

// Invalidate password reset cache
export const invalidatePasswordResetCache = async (email: string, userId?: string): Promise<void> => {
    try {
        const keysToDelete: string[] = [];

        if (email) {
            keysToDelete.push(
                generateKey.passwordResetCode(email),
                `password_reset_attempts:${email}:*`,
                `blocked_password_reset:${email}:*`
            );
        }

        if (userId) {
            keysToDelete.push(`password_reset_tokens:${userId}`);
        }

        // Delete pattern-based keys
        for (const pattern of keysToDelete.filter(k => k.includes('*'))) {
            const matchingKeys = await redisClient.keys(pattern);
            if (matchingKeys.length > 0) {
                await redisClient.del(matchingKeys);
            }
        }

        // Delete direct keys
        const directKeys = keysToDelete.filter(k => !k.includes('*'));
        if (directKeys.length > 0) {
            await redisClient.del(directKeys);
        }

        logger.debug('Password reset cache invalidated successfully', { email, userId });

    } catch (error) {
        logger.error('Failed to invalidate password reset cache', {
            email,
            userId,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};