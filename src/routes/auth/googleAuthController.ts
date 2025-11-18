// backend/src/controllers/googleAuthController.ts - Fixed version
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import User from '../../models/users';
import { GoogleAuthService } from '../../services/googleAuthService';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { AuthRequest } from '../../middlewares/auth';
import { clearUserCache } from '../../utils/cacheUtils';

// Handle Google authentication (both authorization code and direct token flows)
export const googleAuth = async (req: AuthRequest, res: Response) => {
    try {
        const { code, idToken, rememberMe = false } = req.body;

        logger.debug('Google auth attempt', {
            hasCode: !!code,
            hasToken: !!idToken
        });

        if (!code && !idToken) {
            logger.warn('Google auth failed - no code or token provided');
            return res.status(400).json({
                success: false,
                message: 'Google authorization code or token is required'
            });
        }

        let googleUser;
        let usedIdToken = '';

        if (code) {
            logger.debug('Processing authorization code flow');
            try {
                // Exchange authorization code for ID token
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
        } else if (idToken) {
            logger.debug('Processing direct token flow');
            usedIdToken = idToken;
            googleUser = await GoogleAuthService.verifyToken(idToken);
        }

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

        // Find existing user by Google ID or email - without cache for security
        let user = await User.findOne({
            $or: [
                { googleId: googleUser.googleId },
                { email: googleUser.email.toLowerCase() }
            ]
        });

        let requiresPasswordSetup = false;
        let tempToken = '';

        if (!user) {
            logger.debug('New Google user - requiring password setup', {
                email: googleUser.email
            });

            // Create temporary token for new user password setup
            tempToken = jwt.sign(
                {
                    googleUser: {
                        googleId: googleUser.googleId,
                        email: googleUser.email.toLowerCase(),
                        name: googleUser.name || googleUser.email.split('@')[0],
                        picture: googleUser.picture,
                        emailVerified: true
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
            logger.debug('Existing user found for Google auth', {
                userId: user._id.toString(),
                existingProvider: user.authProvider
            });

            // Update user with Google ID if not already set
            if (!user.googleId) {
                user.googleId = googleUser.googleId;
                user.authProvider = 'google';
            }

            user.lastLogin = new Date();
            user.emailVerified = true;

            await user.save();

            // Clear user cache
            await clearUserCache(user._id.toString());

            // Check if password setup is required for existing user
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

        // Generate main authentication token for successful login
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
                emailVerified: true
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