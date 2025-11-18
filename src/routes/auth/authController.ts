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
import { cacheWithFallback, generateKey, CACHE_TTL, clearUserCache, cacheUserWithPassword } from '../../utils/cacheUtils';

// Handle user registration
export const register = async (req: AuthRequest, res: Response) => {
  try {
    const { name, email, password, rememberMe } = req.body;

    logger.debug('Registration attempt', { email, name, rememberMe });

    // Check if user exists - without cache for security
    const existingUser = await User.findOne({ email: email.toLowerCase() });

    if (existingUser) {
      LoggerService.authLog('unknown', 'registration_failed', { reason: 'user_exists', email });
      return res.status(400).json({
        success: false,
        message: 'User already exists'
      });
    }

    // Hash password with pepper for additional security
    const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
      .update(password)
      .digest('hex');
    const hashedPassword = await bcrypt.hash(pepperedPassword, 14);

    // Generate email verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create user with emailVerified: false
    const user = new User({
      name,
      email: email.toLowerCase(),
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

    LoggerService.authLog(user._id.toString(), 'registration_pending', {
      emailVerified: false
    });

    logger.info('New user registered - pending email verification', {
      userId: user._id.toString(),
      email,
    });

    res.status(201).json({
      success: true,
      message: 'Registration successful. Please verify your email.',
      tempToken,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        emailVerified: false
      }
    });
  } catch (error: any) {
    logger.error('Registration error', {
      error: error.message,
      stack: error.stack,
      email: req.body.email
    });
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};

// Handle user login
export const login = async (req: AuthRequest, res: Response) => {
  try {
    const { email, password, rememberMe } = req.body;

    logger.debug('Login attempt', { email, rememberMe });

    // Validate input fields
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user - always read from database for password security
    const user = await cacheUserWithPassword(
      email.toLowerCase(),
      async () => await User.findOne({ email: email.toLowerCase() })
    );

    if (!user) {
      LoggerService.authLog('unknown', 'login_failed', { reason: 'user_not_found', email });
      logger.warn('Login failed - user not found', { email });
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if user is active
    if (!user.isActive) {
      LoggerService.authLog(user._id.toString(), 'login_failed', { reason: 'account_deactivated' });
      return res.status(403).json({
        success: false,
        message: 'Your account has been deactivated. Please contact support.'
      });
    }

    // Check if user has password (for Google users)
    if (!user.password) {
      LoggerService.authLog(user._id.toString(), 'login_failed', { reason: 'no_password_set' });
      return res.status(400).json({
        success: false,
        message: 'Please use Google login or reset your password'
      });
    }

    // Check email verification status
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
        success: false,
        message: 'email-not-verified',
        email: user.email
      });
    }

    // Verify password - now user.password definitely exists
    const pepperedPassword = crypto.createHmac('sha256', process.env.PEPPER_SECRET!)
      .update(password)
      .digest('hex');
    const isPasswordValid = await bcrypt.compare(pepperedPassword, user.password);

    if (!isPasswordValid) {
      LoggerService.authLog(user._id.toString(), 'login_failed', { reason: 'invalid_password' });
      logger.warn('Login failed - invalid password', { userId: user._id.toString(), email });
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate main token only if email is verified
    const expiresIn = rememberMe ? '120d' : '1d';
    const token = jwt.sign(
      { userId: user._id.toString() },
      process.env.JWT_SECRET!,
      { expiresIn }
    );

    // Update last login timestamp
    user.lastLogin = new Date();
    await user.save();

    // Clear user cache
    await clearUserCache(user._id.toString());

    LoggerService.authLog(user._id.toString(), 'login_success', { rememberMe });
    logger.info('User logged in successfully', {
      userId: user._id.toString(),
      email,
      rememberMe: rememberMe || false
    });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      expiresIn,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        role: user.role,
        authProvider: user.authProvider
      }
    });

  } catch (error: any) {
    logger.error('Login error', {
      error: error.message,
      stack: error.stack,
      email: req.body.email
    });

    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
};

// Verify user from token
export const verifyUser = async (req: AuthRequest, res: Response) => {
  try {
    // Get user - without cache for user data security
    const user = await User.findById(req.userId)
      .select('-password -emailVerificationCode -emailVerificationCodeExpires');

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
  } catch (error: any) {
    logger.error('Verify user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during user verification'
    });
  }
};

// Check token validity
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