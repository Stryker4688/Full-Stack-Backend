// backend/src/controllers/authController.ts - Optimized with Redis
import { Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import User from '../../models/users';
import crypto from 'crypto';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { AuthRequest } from '../../middlewares/auth';
import { EmailService } from '../../services/emailService';
import { cacheWithFallback, generateKey, CACHE_TTL, clearUserCache } from '../../utils/cacheUtils';

export const register = async (req: AuthRequest, res: Response) => {
  try {
    const { name, email, password, rememberMe } = req.body;

    logger.debug('Registration attempt', { email, name, rememberMe });

    // Check if user exists with cache
    const existingUser = await cacheWithFallback(
      generateKey.userProfile(`check:${email}`),
      async () => await User.findOne({ email }),
      CACHE_TTL.SHORT
    );

    if (existingUser) {
      LoggerService.authLog('unknown', 'registration_failed', { reason: 'user_exists', email });
      res.status(400).json({ message: 'User already exists' });
      return;
    }

    // Hash password
    const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
      .update(password)
      .digest('hex');
    const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

    // Generate verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create user with emailVerified: false
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

    // Clear any cached user data
    await clearUserCache(user._id.toString());

    // Send verification email
    const emailSent = await EmailService.sendVerificationCode(
      user.email,
      verificationCode,
      user.name
    );

    if (!emailSent) {
      await User.findByIdAndDelete(user._id);
      return res.status(500).json({
        message: 'Failed to send verification email. Please try again.'
      });
    }

    // Generate temporary token
    const tempToken = jwt.sign(
      {
        userId: user._id.toString(),
        type: 'email_verification',
        temp: true
      },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' }
    );

    LoggerService.authLog(user._id.toString(), 'registration_pending', {
      emailVerified: false
    });

    logger.info('New user registered - pending email verification', {
      userId: user._id.toString(),
      email,
    });

    res.status(201).json({
      message: 'Registration successful. Please verify your email.',
      tempToken,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        emailVerified: false
      }
    });
  } catch (error) {
    logger.error('Registration error', { error, email: req.body.email });
    res.status(500).json({ message: 'Server error', error });
  }
};

export const login = async (req: AuthRequest, res: Response) => {
  try {
    const { email, password, rememberMe } = req.body;

    logger.debug('Login attempt', { email, rememberMe });

    // Find user with cache
    const user = await cacheWithFallback(
      generateKey.userProfile(`login:${email}`),
      async () => await User.findOne({ email }),
      CACHE_TTL.SHORT
    );

    if (!user) {
      LoggerService.authLog('unknown', 'login_failed', { reason: 'user_not_found', email });
      logger.warn('Login failed - user not found', { email });
      res.status(400).json({ message: 'Invalid credentials' });
      return;
    }

    // Check email verification
    if (!user.emailVerified) {
      LoggerService.authLog(user._id.toString(), 'login_failed', {
        reason: 'email_not_verified'
      });

      // Resend verification code
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const codeExpires = new Date(Date.now() + 10 * 60 * 1000);

      await User.findByIdAndUpdate(user._id, {
        emailVerificationCode: verificationCode,
        emailVerificationCodeExpires: codeExpires,
        emailVerificationSentAt: new Date()
      });

      // Clear user cache
      await clearUserCache(user._id.toString());

      await EmailService.sendVerificationCode(user.email, verificationCode, user.name);

      return res.status(403).json({
        message: 'email-not-verified',
        email: user.email
      });
    }

    // Check password
    const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
      .update(password)
      .digest('hex');
    const isPasswordValid = await bcrypt.compare(pepperedPassword, user.password);

    if (!isPasswordValid) {
      LoggerService.authLog(user._id.toString(), 'login_failed', { reason: 'invalid_password' });
      logger.warn('Login failed - invalid password', { userId: user._id.toString(), email });
      res.status(400).json({ message: 'invalid-password' });
      return;
    }

    // Generate main token only if email is verified
    const expiresIn = rememberMe ? '120d' : '1d';
    const token = jwt.sign(
      { userId: user._id.toString() },
      process.env.JWT_SECRET!,
      { expiresIn }
    );

    // Update lastLogin
    user.lastLogin = new Date();
    await user.save();

    // Clear and update user cache
    await clearUserCache(user._id.toString());

    LoggerService.authLog(user._id.toString(), 'login_success', { rememberMe });
    logger.info('User logged in successfully', {
      userId: user._id.toString(),
      email,
      rememberMe: rememberMe || false
    });

    res.json({
      message: 'Login successful',
      token,
      expiresIn,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified
      }
    });
  } catch (error) {
    logger.error('Login error', { error, email: req.body.email });
    res.status(500).json({ message: 'Server error', error });
  }
};

export const verifyUser = async (req: AuthRequest, res: Response) => {
  try {
    // Get user with cache
    const user = await cacheWithFallback(
      generateKey.userProfile(req.userId!),
      async () => await User.findById(req.userId).select('-password -emailVerificationCode -emailVerificationCodeExpires'),
      CACHE_TTL.USER_PROFILE
    );

    if (!user) {
      LoggerService.authLog(req.userId!, 'verify_user_failed', { reason: 'user_not_found' });
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    LoggerService.authLog(user._id.toString(), 'user_verified', {
      role: user.role,
      emailVerified: user.emailVerified
    });

    res.json({
      success: true,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified,
        authProvider: user.authProvider,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    logger.error('Verify user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during user verification'
    });
  }
};

export const checkToken = async (req: AuthRequest, res: Response) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      logger.warn('Token check failed - no token provided');
      res.status(401).json({ valid: false, message: 'No token provided' });
      return;
    }

    jwt.verify(token, process.env.JWT_SECRET!, (err: any, decoded: any) => {
      if (err) {
        logger.warn('Token check failed - invalid token', { error: err.message });
        res.status(401).json({ valid: false, message: 'Invalid token' });
        return;
      }

      logger.debug('Token check successful', { userId: decoded.userId });
      res.json({
        valid: true,
        message: 'Token is valid',
        userId: decoded.userId
      });
    });
  } catch (error) {
    logger.error('Token check error:', error);
    res.status(500).json({ valid: false, message: 'Server error' });
  }
};