// backend/src/controllers/emailVerificationController.ts - Complete optimized version
import { Response } from 'express';
import User from '../../models/users';
import { EmailService } from '../../services/emailService';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { AuthRequest } from '../../middlewares/auth';
import jwt from 'jsonwebtoken';
import { redisClient } from '../../config/redis';
import {
    cacheGet,
    cacheSet,
    cacheDelete,
    cacheIncr,
    generateKey,
    CACHE_TTL,
    CACHE_KEYS
} from '../../utils/cacheUtils';

// Manage verification code attempts and blocking
const handleVerificationAttempt = async (email: string, ip: string): Promise<{ blocked: boolean; remainingAttempts: number }> => {
    const attemptKey = generateKey.rateLimit(`verification:${email}:${ip}`);
    const blockKey = generateKey.rateLimit(`blocked_verification:${email}:${ip}`);

    // Check if user is blocked
    const isBlocked = await cacheGet(blockKey);
    if (isBlocked) {
        return { blocked: true, remainingAttempts: 0 };
    }

    // Increment attempt counter
    const attempts = await cacheIncr(attemptKey, 900); // 15 minutes TTL

    // Block user if exceeded maximum attempts
    if (attempts >= 3) {
        await cacheSet(blockKey, 'blocked', 1800); // 30 minutes block
        await cacheDelete(attemptKey);

        logger.warn('User temporarily blocked due to failed verification attempts', {
            email,
            ip,
            attempts
        });

        return { blocked: true, remainingAttempts: 0 };
    }

    return { blocked: false, remainingAttempts: 3 - attempts };
};

// Reset verification attempts on successful verification
const resetVerificationAttempts = async (email: string, ip: string): Promise<void> => {
    const attemptKey = generateKey.rateLimit(`verification:${email}:${ip}`);
    const blockKey = generateKey.rateLimit(`blocked_verification:${email}:${ip}`);

    await Promise.all([
        cacheDelete(attemptKey),
        cacheDelete(blockKey)
    ]);
};

// Process successful email verification
const handleSuccessfulVerification = async (email: string, ip: string, codeData: any): Promise<void> => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            logger.error('User not found during successful verification', { email });
            return;
        }

        // Update user email verification status in database
        await User.findByIdAndUpdate(user._id, {
            emailVerified: true,
            emailVerificationCode: undefined,
            emailVerificationCodeExpires: undefined
        });

        // Remove verification code from cache
        const codeKey = generateKey.verificationCode(email);
        await cacheDelete(codeKey);

        // Reset failed verification attempts
        await resetVerificationAttempts(email, ip);

        // Update verification status in cache
        const statusKey = generateKey.userSession(user._id.toString());
        await cacheSet(statusKey, {
            verified: true,
            verifiedAt: new Date().toISOString()
        }, CACHE_TTL.VERY_LONG);

        // Clear user profile cache to force refresh
        const userCacheKey = generateKey.userProfile(email);
        await cacheDelete(userCacheKey);

        // Send welcome email
        await EmailService.sendWelcomeEmail(user.email, user.name);

        LoggerService.authLog(user._id.toString(), 'email_verified', {
            email: user.email
        });

        logger.info('Email verified successfully', {
            userId: user._id.toString(),
            email: user.email
        });

    } catch (error) {
        logger.error('Error during successful verification processing', {
            email,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

// Process failed verification attempt
const handleFailedVerificationAttempt = async (email: string, ip: string, cachedCode: any, codeKey: string): Promise<void> => {
    try {
        // Increment failed attempts counter
        cachedCode.attempts = (cachedCode.attempts || 0) + 1;

        // Invalidate code if too many failed attempts
        if (cachedCode.attempts >= 3) {
            await cacheDelete(codeKey);

            // Remove code from database as well
            await User.findOneAndUpdate(
                { email: email.toLowerCase() },
                {
                    emailVerificationCode: undefined,
                    emailVerificationCodeExpires: undefined
                }
            );

            logger.warn('Verification code invalidated due to multiple failed attempts', { email });
        } else {
            // Update cache with new attempt count
            await cacheSet(codeKey, cachedCode, 600);
        }

        // Record the failed attempt for rate limiting
        await handleVerificationAttempt(email, ip);

    } catch (error) {
        logger.error('Error during failed verification attempt processing', {
            email,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

// Generate verification response with JWT token
const generateVerificationResponse = async (email: string, userId?: string) => {
    let user = null;

    // Find user by ID or email
    if (userId) {
        user = await User.findById(userId);
    } else {
        user = await User.findOne({ email: email.toLowerCase() });
    }

    if (!user) {
        throw new Error('User not found during verification response generation');
    }

    // Generate main JWT token
    const token = jwt.sign(
        { userId: user._id.toString() },
        process.env.JWT_SECRET!,
        { expiresIn: '120d' }
    );

    // Cache the token
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

export const sendVerificationEmail = async (req: AuthRequest, res: Response) => {
    try {
        // Check authentication
        if (!req.user || !req.user.userId) {
            logger.warn('No user found in request for email verification');
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        const userId = req.user.userId;
        const ip = req.ip || 'unknown';

        logger.debug('Sending verification code for user', { userId, ip });

        // Rate limiting for email sending
        const emailLimitKey = generateKey.rateLimit(`verification_email:${userId}:${ip}`);
        const emailAttempts = await cacheIncr(emailLimitKey, 300); // 5 minutes TTL

        if (emailAttempts > 3) {
            logger.warn('Too many verification email requests', { userId, ip, attempts: emailAttempts });
            return res.status(429).json({
                success: false,
                message: 'Too many verification email requests. Please wait 5 minutes before trying again.'
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

        // Check if email is already verified
        if (user.emailVerified) {
            logger.warn('Email already verified', { userId, email: user.email });
            return res.status(400).json({
                success: false,
                message: 'Email already verified'
            });
        }

        // Generate 6-digit verification code
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        logger.debug('Generated 6-digit verification code', {
            userId,
            email: user.email,
            code: verificationCode
        });

        // Store code in Redis cache
        const codeKey = generateKey.verificationCode(user.email);
        await cacheSet(codeKey, {
            code: verificationCode,
            expiresAt: codeExpires.toISOString(),
            attempts: 0,
            createdAt: new Date().toISOString()
        }, 600); // 10 minutes TTL

        // Update user record with verification code
        await User.findByIdAndUpdate(userId, {
            emailVerificationCode: verificationCode,
            emailVerificationCodeExpires: codeExpires,
            emailVerificationSentAt: new Date()
        });

        // Send verification email
        const emailSent = await EmailService.sendVerificationCode(
            user.email,
            verificationCode,
            user.name
        );

        logger.debug('Email sending result', { emailSent, userId });

        if (!emailSent) {
            // Remove code from cache if email fails
            await cacheDelete(codeKey);
            logger.error('Failed to send verification email', { userId, email: user.email });
            return res.status(500).json({
                success: false,
                message: 'Failed to send verification email. Please try again.'
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
            message: 'Verification code sent successfully. Please check your email.'
        });

    } catch (error) {
        logger.error('Send verification email process failed', {
            error: error instanceof Error ? error.message : 'Unknown error',
            stack: error instanceof Error ? error.stack : undefined,
            userId: req.user?.userId
        });
        res.status(500).json({
            success: false,
            message: 'Server error during verification email process'
        });
    }
};

export const verifyEmailCode = async (req: AuthRequest, res: Response) => {
    try {
        const { code, email } = req.body;
        const ip = req.ip || 'unknown';

        logger.debug('Verifying email code', { email, codeLength: code?.length, ip });

        // Validate input
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
                message: 'Email address is required'
            });
        }

        // Check rate limiting
        const verificationCheck = await handleVerificationAttempt(email, ip);
        if (verificationCheck.blocked) {
            return res.status(429).json({
                success: false,
                message: 'Too many failed verification attempts. Please wait 30 minutes before trying again.'
            });
        }

        // Check cache for verification code first
        const codeKey = generateKey.verificationCode(email);
        const cachedCode = await cacheGet(codeKey);

        if (cachedCode) {
            // Check if cached code has expired
            const expiresAt = new Date(cachedCode.expiresAt);
            if (expiresAt < new Date()) {
                await cacheDelete(codeKey);
                logger.warn('Cached verification code expired', { email });
                return res.status(400).json({
                    success: false,
                    message: 'Verification code has expired. Please request a new one.'
                });
            }

            // Verify code matches
            if (cachedCode.code === code) {
                // Code is correct - process successful verification
                await handleSuccessfulVerification(email, ip, cachedCode);
                const response = await generateVerificationResponse(email, cachedCode.userId);
                return res.json(response);
            } else {
                // Code is incorrect - process failed attempt
                await handleFailedVerificationAttempt(email, ip, cachedCode, codeKey);
                return res.status(400).json({
                    success: false,
                    message: 'Invalid verification code',
                    remainingAttempts: verificationCheck.remainingAttempts - 1
                });
            }
        }

        // If not in cache, check database
        const user = await User.findOne({
            email: email.toLowerCase(),
            emailVerificationCode: code,
            emailVerificationCodeExpires: { $gt: new Date() }
        });

        if (!user) {
            // Increment failed attempts counter
            await handleVerificationAttempt(email, ip);

            // Debug information
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

        // Valid code found in database
        await handleSuccessfulVerification(email, ip, {
            code,
            userId: user._id.toString()
        });

        const response = await generateVerificationResponse(email, user._id.toString());
        res.json(response);

    } catch (error) {
        logger.error('Email verification process failed', {
            error: error instanceof Error ? error.message : 'Unknown error',
            stack: error instanceof Error ? error.stack : undefined,
            email: req.body.email
        });
        res.status(500).json({
            success: false,
            message: 'Server error during email verification process'
        });
    }
};

export const resendVerification = async (req: AuthRequest, res: Response) => {
    try {
        const { email } = req.body;
        const ip = req.ip || 'unknown';

        if (!email) {
            logger.warn('Resend verification - email missing');
            return res.status(400).json({
                success: false,
                message: 'Email address is required'
            });
        }

        // Rate limiting for resend requests
        const resendLimitKey = generateKey.rateLimit(`resend_verification:${email}:${ip}`);
        const resendAttempts = await cacheIncr(resendLimitKey, 300); // 5 minutes TTL

        if (resendAttempts > 2) {
            logger.warn('Too many resend verification requests', { email, ip, attempts: resendAttempts });
            return res.status(429).json({
                success: false,
                message: 'Too many resend requests. Please wait 5 minutes before trying again.'
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

        // Check rate limiting in database (time between sends)
        const lastSent = user.emailVerificationSentAt;
        if (lastSent && Date.now() - lastSent.getTime() < 2 * 60 * 1000) { // 2 minutes
            logger.warn('Resend verification - too frequent', {
                email,
                lastSent: lastSent.toISOString()
            });
            return res.status(429).json({
                success: false,
                message: 'Please wait before requesting another verification code'
            });
        }

        // Generate new verification code
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Store new code in cache
        const codeKey = generateKey.verificationCode(email);
        await cacheSet(codeKey, {
            code: verificationCode,
            expiresAt: codeExpires.toISOString(),
            attempts: 0,
            createdAt: new Date().toISOString()
        }, 600); // 10 minutes TTL

        // Update user record
        await User.findByIdAndUpdate(user._id, {
            emailVerificationCode: verificationCode,
            emailVerificationCodeExpires: codeExpires,
            emailVerificationSentAt: new Date()
        });

        // Send verification email
        const emailSent = await EmailService.sendVerificationCode(
            user.email,
            verificationCode,
            user.name
        );

        if (!emailSent) {
            // Remove code from cache if email fails
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

    } catch (error) {
        logger.error('Resend verification process failed', {
            error: error instanceof Error ? error.message : 'Unknown error',
            stack: error instanceof Error ? error.stack : undefined,
            email: req.body.email
        });
        res.status(500).json({
            success: false,
            message: 'Server error during resend verification process'
        });
    }
};

// Get verification status from cache
export const getVerificationStatus = async (userId: string): Promise<{ verified: boolean; verifiedAt?: string }> => {
    try {
        const statusKey = generateKey.userSession(userId);
        const cachedStatus = await cacheGet(statusKey);

        if (cachedStatus) {
            return cachedStatus;
        }

        // If not in cache, check database
        const user = await User.findById(userId).select('emailVerified emailVerificationSentAt');
        if (!user) {
            return { verified: false };
        }

        const status = {
            verified: user.emailVerified,
            verifiedAt: user.emailVerified ? user.emailVerificationSentAt?.toISOString() : undefined
        };

        // Cache the status for future requests
        await cacheSet(statusKey, status, CACHE_TTL.LONG);

        return status;
    } catch (error) {
        logger.error('Failed to get verification status', {
            userId,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
        return { verified: false };
    }
};

// Invalidate all verification-related cache
export const invalidateVerificationCache = async (email: string, userId?: string): Promise<void> => {
    try {
        const keysToDelete: string[] = [];

        if (email) {
            keysToDelete.push(
                generateKey.verificationCode(email),
                `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:${email}:*`,
                `${CACHE_KEYS.BLOCKED_VERIFICATION}:${email}:*`,
                `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:send:*:${email}`,
                `${CACHE_KEYS.VERIFICATION_ATTEMPTS}:resend:${email}:*`
            );
        }

        if (userId) {
            keysToDelete.push(
                generateKey.userSession(userId),
                `${CACHE_KEYS.TEMP_TOKENS}:${userId}`
            );
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

        logger.debug('Verification cache invalidated successfully', { email, userId });

    } catch (error) {
        logger.error('Failed to invalidate verification cache', {
            email,
            userId,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};