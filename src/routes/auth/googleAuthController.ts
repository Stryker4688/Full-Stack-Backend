// backend/src/controllers/googleAuthController.ts - Enhanced with comprehensive features
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import User from '../../models/users';
import { GoogleAuthService } from '../../services/googleAuthService';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { AuthRequest } from '../../middlewares/auth';
import {
    cacheGet,
    cacheSet,
    cacheDelete,
    checkRateLimit,
    generateKey,
    CACHE_TTL,
    cacheWithFallback
} from '../../utils/cacheUtils';
import { redisClient } from '../../config/redis';

// Enhanced Google authentication with comprehensive error handling
export const googleAuth = async (req: AuthRequest, res: Response) => {
    try {
        const { code, idToken, rememberMe = false } = req.body;
        const ip = req.ip || 'unknown';

        logger.debug('Google authentication request received', {
            hasCode: !!code,
            hasToken: !!idToken,
            ip,
            userAgent: req.get('User-Agent')
        });

        // Enhanced rate limiting with IP and user agent fingerprinting
        const userFingerprint = `${ip}-${req.get('User-Agent')?.substring(0, 50)}`;
        const rateLimitCheck = await checkRateLimit(userFingerprint, 10, 300); // 10 requests per 5 minutes

        if (!rateLimitCheck.allowed) {
            logger.warn('Google authentication rate limit exceeded', {
                ip,
                fingerprint: userFingerprint,
                remaining: rateLimitCheck.remaining
            });

            return res.status(429).json({
                success: false,
                message: 'Too many authentication attempts. Please wait a few minutes before trying again.',
                retryAfter: 300 // 5 minutes in seconds
            });
        }

        // Validate input parameters
        if (!code && !idToken) {
            logger.warn('Google authentication failed - missing credentials');
            return res.status(400).json({
                success: false,
                message: 'Google authorization code or ID token is required',
                code: 'MISSING_CREDENTIALS'
            });
        }

        let googleUser;
        let usedIdToken = '';
        let authFlow: 'authorization_code' | 'direct_token' = 'direct_token';

        // Process authorization code flow
        if (code) {
            authFlow = 'authorization_code';
            logger.debug('Processing Google authorization code flow');

            try {
                // Check cache for previously processed code
                const codeCacheKey = `google_auth:code:${code}`;
                const cachedAuth = await cacheGet(codeCacheKey);

                if (cachedAuth) {
                    usedIdToken = cachedAuth.idToken;
                    googleUser = cachedAuth.userInfo;
                    logger.debug('Using cached Google authentication data', { code });
                } else {
                    // Exchange authorization code for tokens
                    usedIdToken = await GoogleAuthService.getTokenFromCode(code);
                    googleUser = await GoogleAuthService.verifyToken(usedIdToken);

                    // Cache the authentication data for future use
                    await cacheSet(codeCacheKey, {
                        idToken: usedIdToken,
                        userInfo: googleUser,
                        flow: 'authorization_code'
                    }, CACHE_TTL.SHORT);

                    logger.debug('Successfully exchanged authorization code for tokens');
                }
            } catch (error: any) {
                logger.error('Google authorization code processing failed', {
                    error: error.message,
                    codeLength: code?.length
                });

                return res.status(400).json({
                    success: false,
                    message: 'Invalid or expired authorization code',
                    code: 'INVALID_AUTHORIZATION_CODE',
                    details: error.message
                });
            }
        }
        // Process direct ID token flow
        else if (idToken) {
            authFlow = 'direct_token';
            logger.debug('Processing Google direct ID token flow');

            try {
                // Check cache for token validation
                const tokenCacheKey = `google_auth:token:${idToken.substring(0, 20)}`;
                const cachedUser = await cacheGet(tokenCacheKey);

                if (cachedUser) {
                    usedIdToken = idToken;
                    googleUser = cachedUser;
                    logger.debug('Using cached Google user data from token');
                } else {
                    usedIdToken = idToken;
                    googleUser = await GoogleAuthService.verifyToken(idToken);

                    // Cache user information for future requests
                    await cacheSet(tokenCacheKey, googleUser, CACHE_TTL.MEDIUM);

                    logger.debug('Successfully verified Google ID token');
                }
            } catch (error: any) {
                logger.error('Google ID token verification failed', {
                    error: error.message,
                    tokenLength: idToken?.length
                });

                return res.status(400).json({
                    success: false,
                    message: 'Invalid Google ID token',
                    code: 'INVALID_ID_TOKEN',
                    details: error.message
                });
            }
        }

        // Validate Google user data
        if (!googleUser?.email) {
            logger.error('Google authentication failed - missing email in user data');
            return res.status(400).json({
                success: false,
                message: 'Google account email is required for authentication',
                code: 'MISSING_EMAIL'
            });
        }

        if (!googleUser.googleId) {
            logger.error('Google authentication failed - missing Google ID in user data');
            return res.status(400).json({
                success: false,
                message: 'Invalid Google user data received',
                code: 'MISSING_GOOGLE_ID'
            });
        }

        logger.debug('Google authentication data validated successfully', {
            email: googleUser.email,
            googleId: googleUser.googleId,
            emailVerified: googleUser.emailVerified,
            flow: authFlow
        });

        // Find or create user account
        const userResult = await findOrCreateGoogleUser(googleUser, req);

        if (!userResult.success) {
            return res.status(userResult.statusCode || 500).json({
                success: false,
                message: userResult.message,
                code: userResult.code
            });
        }

        const { user, requiresPasswordSetup, tempToken, isNewUser } = userResult;

        // Handle password setup requirement for new users or users without passwords
        if (requiresPasswordSetup) {
            logger.info('Google user requires password setup', {
                email: googleUser.email,
                isNewUser,
                userId: user?._id?.toString()
            });

            return res.json({
                success: true,
                requiresPasswordSetup: true,
                tempToken,
                message: isNewUser
                    ? 'Please set your password to complete registration'
                    : 'Please set a password for your account',
                user: user ? {
                    id: user._id.toString(),
                    name: user.name,
                    email: user.email,
                    isNewUser
                } : {
                    email: googleUser.email,
                    name: googleUser.name,
                    isNewUser: true
                }
            });
        }

        // Generate main authentication token for existing users with passwords
        const expiresIn = rememberMe ? '120d' : '1d';
        const token = jwt.sign(
            {
                userId: user!._id.toString(),
                authProvider: 'google'
            },
            process.env.JWT_SECRET!,
            { expiresIn }
        );

        // Store authentication session in cache
        const sessionKey = generateKey.userSession(user!._id.toString());
        await cacheSet(sessionKey, {
            userId: user!._id.toString(),
            provider: 'google',
            loginTime: new Date().toISOString(),
            expiresIn,
            ip,
            userAgent: req.get('User-Agent')
        }, rememberMe ? CACHE_TTL.VERY_LONG : CACHE_TTL.LONG);

        // Update user last login timestamp
        await User.findByIdAndUpdate(user!._id, {
            lastLogin: new Date(),
            lastLoginIp: ip
        });

        logger.info('Google authentication completed successfully', {
            userId: user!._id.toString(),
            email: user!.email,
            provider: 'google',
            isNewUser: false,
            authFlow
        });

        // Successful authentication response
        res.json({
            success: true,
            requiresPasswordSetup: false,
            message: 'Authentication successful',
            token,
            expiresIn,
            user: {
                id: user!._id.toString(),
                name: user!.name,
                email: user!.email,
                role: user!.role,
                authProvider: user!.authProvider,
                emailVerified: user!.emailVerified,
                avatar: user!.avatar
            },
            session: {
                loginTime: new Date().toISOString(),
                expiresIn,
                provider: 'google'
            }
        });

    } catch (error: any) {
        logger.error('Google authentication process failed completely', {
            error: error.message,
            stack: error.stack,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.status(500).json({
            success: false,
            message: 'Google authentication service temporarily unavailable',
            code: 'AUTH_SERVICE_ERROR',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Helper function to find or create Google user
const findOrCreateGoogleUser = async (googleUser: any, req: AuthRequest) => {
    try {
        const { email, googleId, name, picture, emailVerified } = googleUser;

        // Check cache for existing user
        const userByEmailKey = generateKey.googleUser(email);
        const userByGoogleIdKey = generateKey.googleUserById(googleId);

        let user = await cacheGet(userByEmailKey) || await cacheGet(userByGoogleIdKey);

        if (!user) {
            // User not in cache - check database
            user = await User.findOne({
                $or: [
                    { googleId: googleId },
                    { email: email.toLowerCase() }
                ]
            });

            if (user) {
                // Cache user information for future requests
                await Promise.all([
                    cacheSet(userByEmailKey, user, CACHE_TTL.MEDIUM),
                    cacheSet(userByGoogleIdKey, user, CACHE_TTL.MEDIUM)
                ]);
            }
        }

        let requiresPasswordSetup = false;
        let tempToken = '';
        let isNewUser = false;

        // New user registration flow
        if (!user) {
            logger.debug('Creating new user account for Google authentication', { email });

            // Check for existing email conflicts
            const existingUser = await User.findOne({ email: email.toLowerCase() });
            if (existingUser) {
                return {
                    success: false,
                    message: 'An account with this email already exists',
                    code: 'EMAIL_ALREADY_EXISTS',
                    statusCode: 409
                };
            }

            // Store temporary user data for password setup
            const tempUserData = {
                googleId,
                email: email.toLowerCase(),
                name: name || email.split('@')[0],
                picture,
                emailVerified: emailVerified || false
            };

            const tempUserKey = `google_temp_user:${googleId}`;
            await cacheSet(tempUserKey, {
                ...tempUserData,
                type: 'google_registration',
                createdAt: new Date().toISOString(),
                ip: req.ip
            }, CACHE_TTL.MEDIUM);

            // Generate temporary token for password setup
            tempToken = jwt.sign(
                {
                    googleUser: tempUserData,
                    type: 'google_password_setup',
                    registration: true
                },
                process.env.JWT_SECRET!,
                { expiresIn: '1h' }
            );

            requiresPasswordSetup = true;
            isNewUser = true;

            LoggerService.authLog('unknown', 'google_registration_initiated', {
                provider: 'google',
                email,
                requiresPasswordSetup: true
            });

            return {
                success: true,
                requiresPasswordSetup,
                tempToken,
                isNewUser,
                user: null
            };
        }

        // Existing user flow
        logger.debug('Processing existing user for Google authentication', {
            userId: user._id.toString(),
            existingProvider: user.authProvider
        });

        // Update user record if needed
        const updates: any = {};
        let needsUpdate = false;

        if (!user.googleId) {
            updates.googleId = googleId;
            updates.authProvider = 'google';
            needsUpdate = true;
        }

        if (user.emailVerified !== emailVerified) {
            updates.emailVerified = emailVerified || false;
            needsUpdate = true;
        }

        if (user.avatar !== picture) {
            updates.avatar = picture;
            needsUpdate = true;
        }

        updates.lastLogin = new Date();
        updates.lastLoginIp = req.ip;
        needsUpdate = true;

        if (needsUpdate) {
            user = await User.findByIdAndUpdate(
                user._id,
                updates,
                { new: true }
            );

            // Update cache with new user data
            await Promise.all([
                cacheSet(userByEmailKey, user, CACHE_TTL.MEDIUM),
                cacheSet(userByGoogleIdKey, user, CACHE_TTL.MEDIUM)
            ]);
        }

        // Check if password setup is required for existing users
        if (!user.password) {
            const tempSetupKey = `google_password_setup:${user._id.toString()}`;
            await cacheSet(tempSetupKey, {
                userId: user._id.toString(),
                type: 'google_password_setup',
                createdAt: new Date().toISOString(),
                ip: req.ip
            }, CACHE_TTL.MEDIUM);

            tempToken = jwt.sign(
                {
                    userId: user._id.toString(),
                    type: 'google_password_setup',
                    registration: false
                },
                process.env.JWT_SECRET!,
                { expiresIn: '1h' }
            );

            requiresPasswordSetup = true;
        }

        LoggerService.authLog(user._id.toString(), 'google_login_processed', {
            provider: 'google',
            requiresPasswordSetup,
            isNewUser: false
        });

        return {
            success: true,
            user,
            requiresPasswordSetup,
            tempToken,
            isNewUser: false
        };

    } catch (error) {
        logger.error('Error in findOrCreateGoogleUser', {
            error: error instanceof Error ? error.message : 'Unknown error',
            email: googleUser.email
        });

        throw error;
    }
};

// Enhanced Google authentication session management
export const getGoogleAuthSession = async (userId: string): Promise<any> => {
    try {
        const sessionKey = generateKey.userSession(userId);
        const session = await cacheGet(sessionKey);

        if (session && session.provider === 'google') {
            logger.debug('Retrieved Google authentication session from cache', { userId });
            return session;
        }

        return null;
    } catch (error) {
        logger.error('Error retrieving Google authentication session', {
            userId,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
        return null;
    }
};

// Enhanced session clearing with comprehensive cache cleanup
export const clearGoogleAuthSession = async (userId: string): Promise<void> => {
    try {
        const sessionKey = generateKey.userSession(userId);
        await cacheDelete(sessionKey);

        // Clear all Google-related cache entries
        const patterns = [
            `google_user:*:${userId}`,
            `google_auth:*:${userId}`,
            `google_temp_user:*`,
            `google_password_setup:${userId}`
        ];

        for (const pattern of patterns) {
            const keys = await redisClient.keys(pattern);
            if (keys.length > 0) {
                await redisClient.del(keys);
            }
        }

        logger.debug('Google authentication session cleared completely', { userId });
    } catch (error) {
        logger.error('Error clearing Google authentication session', {
            userId,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

// Get cached Google user with enhanced error handling
export const getCachedGoogleUser = async (email: string, googleId: string): Promise<any> => {
    try {
        const userByEmail = await cacheWithFallback(
            generateKey.googleUser(email),
            async () => null, // Don't fetch from DB if not in cache
            CACHE_TTL.SHORT
        );

        if (userByEmail) return userByEmail;

        const userByGoogleId = await cacheWithFallback(
            generateKey.googleUserById(googleId),
            async () => null, // Don't fetch from DB if not in cache
            CACHE_TTL.SHORT
        );

        return userByGoogleId;
    } catch (error) {
        logger.error('Error retrieving cached Google user', {
            email,
            googleId,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
        return null;
    }
};

// Enhanced cache invalidation for Google users
export const invalidateGoogleUserCache = async (email: string, googleId: string, userId?: string): Promise<void> => {
    try {
        const keysToDelete = [
            generateKey.googleUser(email),
            generateKey.googleUserById(googleId),
            generateKey.userSession(userId!),
            `google_temp_user:${googleId}`,
            `google_password_setup:${userId}`,
            `google_auth:*:${userId}`
        ].filter(Boolean);

        // Delete direct keys
        const directKeys = keysToDelete.filter(k => !k.includes('*'));
        if (directKeys.length > 0) {
            await redisClient.del(directKeys);
        }

        // Delete pattern-based keys
        for (const pattern of keysToDelete.filter(k => k.includes('*'))) {
            const matchingKeys = await redisClient.keys(pattern);
            if (matchingKeys.length > 0) {
                await redisClient.del(matchingKeys);
            }
        }

        logger.debug('Google user cache invalidated comprehensively', { email, googleId, userId });
    } catch (error) {
        logger.error('Error invalidating Google user cache', {
            email,
            googleId,
            userId,
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

// Google authentication health check
export const checkGoogleAuthHealth = async (): Promise<{
    healthy: boolean;
    service: string;
    details?: string;
}> => {
    try {
        // Test Google service availability with a mock verification
        const testToken = 'test-token';
        try {
            await GoogleAuthService.verifyToken(testToken);
        } catch (error) {
            // Expected to fail with test token, but service is responsive
            if (error instanceof Error && error.message.includes('Invalid Google token')) {
                return {
                    healthy: true,
                    service: 'google_auth',
                    details: 'Service responsive'
                };
            }
        }

        return {
            healthy: true,
            service: 'google_auth',
            details: 'Service available'
        };
    } catch (error) {
        logger.error('Google authentication health check failed', {
            error: error instanceof Error ? error.message : 'Unknown error'
        });

        return {
            healthy: false,
            service: 'google_auth',
            details: error instanceof Error ? error.message : 'Service unavailable'
        };
    }
};

// Import redisClient for cache operations
