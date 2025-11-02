// backend/src/controllers/authController.ts - Optimized with cache utilities
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import User from '../../models/users';
import crypto from 'crypto';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { AuthRequest } from '../../middlewares/auth';
import { EmailService } from '../../services/emailService';
import { redisClient } from '../../config/redis';
import {
  cacheGet,
  cacheSet,
  cacheDelete,
  cacheIncr,
  clearUserCache,
  clearAuthCache,
  clearUserCacheByEmail,
  generateKey,
  CACHE_TTL,
  CACHE_KEYS
} from '../../utils/cacheUtils';

// Manage failed login attempts
const handleFailedLogin = async (email: string, ip: string): Promise<{ blocked: boolean; remainingAttempts: number }> => {
  const attemptKey = generateKey.rateLimit(`login:${email}:${ip}`);
  const blockKey = generateKey.rateLimit(`blocked:${email}:${ip}`);

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

    logger.warn('User temporarily blocked due to failed login attempts', {
      email,
      ip,
      attempts
    });

    return { blocked: true, remainingAttempts: 0 };
  }

  return { blocked: false, remainingAttempts: 5 - attempts };
};

// Reset failed login attempts on successful login
const resetFailedLogin = async (email: string, ip: string): Promise<void> => {
  const attemptKey = generateKey.rateLimit(`login:${email}:${ip}`);
  const blockKey = generateKey.rateLimit(`blocked:${email}:${ip}`);

  await Promise.all([
    cacheDelete(attemptKey),
    cacheDelete(blockKey)
  ]);
};

export const register = async (req: AuthRequest, res: Response) => {
  try {
    const { name, email, password, rememberMe } = req.body;

    logger.debug('Registration attempt received', { email, name, rememberMe });

    // Check cache for existing user
    const userProfileKey = generateKey.userProfile(email);
    const existingUserCached = await cacheGet(userProfileKey);

    if (existingUserCached) {
      LoggerService.authLog('unknown', 'registration_failed', { reason: 'user_exists', email });
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Check database for existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      // Cache existence to prevent duplicate checks
      await cacheSet(userProfileKey, { exists: true }, CACHE_TTL.SHORT);

      LoggerService.authLog('unknown', 'registration_failed', { reason: 'user_exists', email });
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Hash password with pepper for additional security
    const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
      .update(password)
      .digest('hex');
    const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

    // Generate 6-digit verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create new user with unverified email
    const user = new User({
      name,
      email,
      password: hashedPassword,
      emailVerified: false,
      emailVerificationCode: verificationCode,
      emailVerificationCodeExpires: codeExpires,
      emailVerificationSentAt: new Date()
    });

    await user.save();

    // Cache user information
    await cacheSet(userProfileKey, {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      emailVerified: user.emailVerified
    }, CACHE_TTL.MEDIUM);

    // Send verification email
    const emailSent = await EmailService.sendVerificationCode(
      user.email,
      verificationCode,
      user.name
    );

    if (!emailSent) {
      // Rollback user creation if email fails
      await User.findByIdAndDelete(user._id);
      await cacheDelete(userProfileKey);
      return res.status(500).json({
        success: false,
        message: 'Failed to send verification email. Please try again.'
      });
    }

    // Generate temporary token for email verification flow
    const tempToken = jwt.sign(
      {
        userId: user._id.toString(),
        type: 'email_verification',
        temp: true
      },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' }
    );

    // Cache temporary token
    const tempTokenKey = generateKey.userSession(user._id.toString());
    await cacheSet(tempTokenKey, {
      token: tempToken,
      type: 'email_verification',
      createdAt: new Date().toISOString()
    }, 3600); // 1 hour TTL

    LoggerService.authLog(user._id.toString(), 'registration_pending', {
      emailVerified: false
    });

    logger.info('New user registered - pending email verification', {
      userId: user._id.toString(),
      email,
    });

    res.status(201).json({
      success: true,
      message: 'Registration successful. Please check your email for verification code.',
      tempToken,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        emailVerified: false
      }
    });
  } catch (error) {
    logger.error('Registration process failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      email: req.body.email
    });
    res.status(500).json({
      success: false,
      message: 'Server error during registration process',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
};

export const login = async (req: AuthRequest, res: Response) => {
  try {
    const { email, password, rememberMe } = req.body;
    const ip = req.ip || 'unknown';

    logger.debug('Login attempt received', { email, rememberMe, ip });

    // Check rate limiting and blocking
    const loginCheck = await handleFailedLogin(email, ip);
    if (loginCheck.blocked) {
      return res.status(429).json({
        success: false,
        message: 'Your account has been temporarily blocked due to multiple failed login attempts. Please try again in 30 minutes.'
      });
    }

    // Check cache for user information
    const userProfileKey = generateKey.userProfile(email);
    let user = await cacheGet(userProfileKey);

    if (!user) {
      // Fetch from database if not in cache
      const dbUser = await User.findOne({ email });
      if (!dbUser) {
        LoggerService.authLog('unknown', 'login_failed', { reason: 'user_not_found', email });
        logger.warn('Login failed - user not found', { email });

        // Increment failed attempts
        await handleFailedLogin(email, ip);

        return res.status(400).json({
          success: false,
          message: 'Invalid email or password'
        });
      }

      user = {
        id: dbUser._id.toString(),
        name: dbUser.name,
        email: dbUser.email,
        password: dbUser.password,
        emailVerified: dbUser.emailVerified,
        isActive: dbUser.isActive,
        role: dbUser.role
      };

      // Cache user information for future requests
      await cacheSet(userProfileKey, user, CACHE_TTL.MEDIUM);
    }

    // Check if email is verified
    if (!user.emailVerified) {
      LoggerService.authLog(user.id, 'login_failed', {
        reason: 'email_not_verified'
      });

      // Generate and send new verification code
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const codeExpires = new Date(Date.now() + 10 * 60 * 1000);

      await User.findByIdAndUpdate(user.id, {
        emailVerificationCode: verificationCode,
        emailVerificationCodeExpires: codeExpires,
        emailVerificationSentAt: new Date()
      });

      await EmailService.sendVerificationCode(user.email, verificationCode, user.name);

      // Update cache with new verification code
      await cacheSet(userProfileKey, {
        ...user,
        emailVerificationCode: verificationCode
      }, CACHE_TTL.SHORT);

      return res.status(403).json({
        success: false,
        message: 'email-not-verified',
        email: user.email
      });
    }

    // Verify password with pepper
    const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
      .update(password)
      .digest('hex');
    const isPasswordValid = await bcrypt.compare(pepperedPassword, user.password);

    if (!isPasswordValid) {
      LoggerService.authLog(user.id, 'login_failed', { reason: 'invalid_password' });
      logger.warn('Login failed - invalid password', { userId: user.id, email });

      // Increment failed attempts counter
      await handleFailedLogin(email, ip);

      return res.status(400).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Reset failed attempts on successful login
    await resetFailedLogin(email, ip);

    // Generate JWT token
    const expiresIn = rememberMe ? '120d' : '1d';
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET!,
      { expiresIn }
    );

    // Update last login timestamp
    await User.findByIdAndUpdate(user.id, { lastLogin: new Date() });

    // Update cache with latest user data
    await cacheSet(userProfileKey, {
      ...user,
      lastLogin: new Date().toISOString()
    }, CACHE_TTL.MEDIUM);

    LoggerService.authLog(user.id, 'login_success', { rememberMe });
    logger.info('User logged in successfully', {
      userId: user.id,
      email,
      rememberMe: rememberMe || false
    });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      expiresIn,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified
      }
    });
  } catch (error) {
    logger.error('Login process failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      email: req.body.email
    });
    res.status(500).json({
      success: false,
      message: 'Server error during login process',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
};

export const checkToken = async (req: AuthRequest, res: Response) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      logger.warn('Token validation failed - no token provided');
      return res.status(401).json({
        valid: false,
        message: 'No authentication token provided'
      });
    }

    // Check cache for token validation
    const tokenKey = `${CACHE_KEYS.TEMP_TOKENS}:${req.userId}`;
    const cachedToken = await cacheGet(tokenKey);

    if (cachedToken && cachedToken.token === token) {
      logger.debug('Token validated from cache', { userId: req.userId });
      return res.json({
        valid: true,
        message: 'Token is valid',
        userId: req.userId,
        fromCache: true
      });
    }

    // Verify token with JWT
    jwt.verify(token, process.env.JWT_SECRET!, (err: any, decoded: any) => {
      if (err) {
        logger.warn('Token validation failed - invalid token', { error: err.message });
        return res.status(401).json({
          valid: false,
          message: 'Invalid or expired token'
        });
      }

      // Cache valid token for future validations
      cacheSet(tokenKey, {
        token: token,
        type: 'access_token',
        validatedAt: new Date().toISOString()
      }, CACHE_TTL.SHORT).catch(() => { });

      logger.debug('Token validation successful', { userId: decoded.userId });
      res.json({
        valid: true,
        message: 'Token is valid',
        userId: decoded.userId,
        fromCache: false
      });
    });
  } catch (error) {
    logger.error('Token validation process failed', {
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    res.status(500).json({
      valid: false,
      message: 'Server error during token validation'
    });
  }
};

export const logout = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.userId;
    const token = req.headers['authorization']?.split(' ')[1];

    if (userId && token) {
      // Clear token from cache
      const tokenKey = `${CACHE_KEYS.TEMP_TOKENS}:${userId}`;
      await cacheDelete(tokenKey);

      // Clear user session
      await clearAuthCache(userId, 'user');
    }

    LoggerService.authLog(userId || 'unknown', 'logout_success');

    res.json({
      success: true,
      message: 'Logout successful'
    });

  } catch (error) {
    logger.error('Logout process failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: req.userId
    });
    res.status(500).json({
      success: false,
      message: 'Server error during logout process'
    });
  }
};

// Utility function to get user from cache
export const getUserFromCache = async (userId: string): Promise<any> => {
  try {
    // Search through cache keys to find user
    const keys = await redisClient.keys(`${CACHE_KEYS.USER_PROFILE}:*`);

    for (const key of keys) {
      const user = await cacheGet(key);
      if (user && user.id === userId) {
        return user;
      }
    }
    return null;
  } catch (error) {
    logger.error('Failed to get user from cache', {
      userId,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    return null;
  }
};

// Utility function to invalidate user authentication cache
export const invalidateUserAuthCache = async (userId: string, email?: string): Promise<void> => {
  try {
    if (email) {
      await clearUserCacheByEmail(email);
    }
    if (userId) {
      await clearUserCache(userId);
    }

    logger.debug('User authentication cache invalidated successfully', { userId, email });
  } catch (error) {
    logger.error('Failed to invalidate user authentication cache', {
      userId,
      email,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
};