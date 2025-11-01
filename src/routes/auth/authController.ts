// backend/src/controllers/authController.ts
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import User from '../../models/users';
import crypto from 'crypto';
import { LoggerService } from '../../services/loggerServices';
import { logger } from '../../config/logger';
import { AuthRequest } from '../../middlewares/auth';
import { EmailService } from '../../services/emailService';

export const register = async (req: AuthRequest, res: Response) => {
  try {
    const { name, email, password, rememberMe } = req.body;

    logger.debug('Registration attempt', { email, name, rememberMe });

    // Check if user exists
    const existingUser = await User.findOne({ email });
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

    // تولید کد تأیید
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 دقیقه

    // Create user با emailVerified: false
    const user = new User({
      name,
      email,
      password: hashedPassword,
      emailVerified: false, // مهم: ابتدا false
      emailVerificationCode: verificationCode,
      emailVerificationCodeExpires: codeExpires,
      emailVerificationSentAt: new Date()
    });

    await user.save();

    // ارسال ایمیل تأیید
    const emailSent = await EmailService.sendVerificationCode(
      user.email,
      verificationCode,
      user.name
    );

    if (!emailSent) {
      // اگر ایمیل ارسال نشد، کاربر رو پاک کن
      await User.findByIdAndDelete(user._id);
      return res.status(500).json({
        message: 'Failed to send verification email. Please try again.'
      });
    }

    // 🔥 تولید توکن موقت (نه توکن اصلی)
    const tempToken = jwt.sign(
      {
        userId: user._id.toString(),
        type: 'email_verification',
        temp: true
      },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' } // فقط 1 ساعت اعتبار
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
      tempToken, // توکن موقت
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        emailVerified: false // مهم
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

    // Find user
    const user = await User.findOne({ email });
    const existingAdmin = await User.findOne({
      $or: [
        { email: process.env.SUPER_ADMIN_EMAIL },
        { role: "super_admin" }
      ]
    });
    if (!user) {
      LoggerService.authLog('unknown', 'login_failed', { reason: 'user_not_found', email });
      logger.warn('Login failed - user not found', { email });
      res.status(400).json({ message: 'Invalid credentials' });
      return;
    }

    // 🔥 چک کردن تأیید ایمیل
    if (!user.emailVerified) {
      LoggerService.authLog(user._id.toString(), 'login_failed', {
        reason: 'email_not_verified'
      });

      // ارسال مجدد کد تأیید
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const codeExpires = new Date(Date.now() + 10 * 60 * 1000);

      await User.findByIdAndUpdate(user._id, {
        emailVerificationCode: verificationCode,
        emailVerificationCodeExpires: codeExpires,
        emailVerificationSentAt: new Date()
      });

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

    // 🔥 فقط اگر ایمیل تأیید شده باشد، توکن اصلی تولید کن
    const expiresIn = rememberMe ? '120d' : '1d';
    const token = jwt.sign(
      { userId: user._id.toString() },
      process.env.JWT_SECRET!,
      { expiresIn }
    );

    // آپدیت lastLogin
    user.lastLogin = new Date();
    await user.save();

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
        emailVerified: user.emailVerified // true
      }
    });
  } catch (error) {
    logger.error('Login error', { error, email: req.body.email });
    res.status(500).json({ message: 'Server error', error });
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