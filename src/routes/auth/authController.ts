// backend/src/controllers/authController.ts - بهینه‌سازی شده با Redis
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

// کلیدهای کش
const CACHE_KEYS = {
  USER_PROFILE: 'user_profile',
  LOGIN_ATTEMPTS: 'login_attempts',
  TEMP_TOKENS: 'temp_tokens',
  BLOCKED_USERS: 'blocked_users'
};

// زمان انقضای کش (ثانیه)
const CACHE_TTL = {
  SHORT: 300,      // 5 دقیقه
  MEDIUM: 1800,    // 30 دقیقه
  LONG: 86400,     // 24 ساعت
  VERY_LONG: 604800 // 7 روز
};

// توابع کمکی کش
const cacheGet = async (key: string): Promise<any> => {
  try {
    const cached = await redisClient.get(key);
    return cached ? JSON.parse(cached) : null;
  } catch (error) {
    logger.error('Cache get error', { key, error });
    return null;
  }
};

const cacheSet = async (key: string, data: any, ttl: number = CACHE_TTL.MEDIUM): Promise<void> => {
  try {
    await redisClient.setEx(key, ttl, JSON.stringify(data));
  } catch (error) {
    logger.error('Cache set error', { key, error });
  }
};

const cacheDelete = async (key: string): Promise<void> => {
  try {
    await redisClient.del(key);
  } catch (error) {
    logger.error('Cache delete error', { key, error });
  }
};

// تابع برای مدیریت تلاش‌های ناموفق لاگین
const handleFailedLogin = async (email: string, ip: string): Promise<{ blocked: boolean; remainingAttempts: number }> => {
  const attemptKey = `${CACHE_KEYS.LOGIN_ATTEMPTS}:${email}:${ip}`;
  const blockKey = `${CACHE_KEYS.BLOCKED_USERS}:${email}:${ip}`;

  // بررسی اگر کاربر بلاک شده
  const isBlocked = await redisClient.get(blockKey);
  if (isBlocked) {
    return { blocked: true, remainingAttempts: 0 };
  }

  // افزایش تعداد تلاش‌ها
  const attempts = await redisClient.incr(attemptKey);

  // اگر اولین تلاش است، TTL تنظیم کن
  if (attempts === 1) {
    await redisClient.expire(attemptKey, 900); // 15 دقیقه
  }

  // اگر بیش از 5 تلاش ناموفق، کاربر را بلاک کن
  if (attempts >= 5) {
    await redisClient.setEx(blockKey, 1800, 'blocked'); // 30 دقیقه بلاک
    await redisClient.del(attemptKey);

    logger.warn('User temporarily blocked due to failed login attempts', {
      email,
      ip,
      attempts
    });

    return { blocked: true, remainingAttempts: 0 };
  }

  return { blocked: false, remainingAttempts: 5 - attempts };
};

// تابع برای ریست کردن تلاش‌های ناموفق
const resetFailedLogin = async (email: string, ip: string): Promise<void> => {
  const attemptKey = `${CACHE_KEYS.LOGIN_ATTEMPTS}:${email}:${ip}`;
  const blockKey = `${CACHE_KEYS.BLOCKED_USERS}:${email}:${ip}`;

  await Promise.all([
    redisClient.del(attemptKey),
    redisClient.del(blockKey)
  ]);
};

export const register = async (req: AuthRequest, res: Response) => {
  try {
    const { name, email, password, rememberMe } = req.body;

    logger.debug('Registration attempt', { email, name, rememberMe });

    // بررسی کش برای کاربر موجود
    const userProfileKey = `${CACHE_KEYS.USER_PROFILE}:${email}`;
    const existingUserCached = await cacheGet(userProfileKey);

    if (existingUserCached) {
      LoggerService.authLog('unknown', 'registration_failed', { reason: 'user_exists', email });
      res.status(400).json({ message: 'User already exists' });
      return;
    }

    // Check if user exists in database
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      // ذخیره در کش برای جلوگیری از چک‌های تکراری
      await cacheSet(userProfileKey, { exists: true }, CACHE_TTL.SHORT);

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
      emailVerified: false,
      emailVerificationCode: verificationCode,
      emailVerificationCodeExpires: codeExpires,
      emailVerificationSentAt: new Date()
    });

    await user.save();

    // 🔥 ذخیره اطلاعات کاربر در کش
    await cacheSet(userProfileKey, {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      emailVerified: user.emailVerified
    }, CACHE_TTL.MEDIUM);

    // ارسال ایمیل تأیید
    const emailSent = await EmailService.sendVerificationCode(
      user.email,
      verificationCode,
      user.name
    );

    if (!emailSent) {
      // اگر ایمیل ارسال نشد، کاربر رو پاک کن و کش رو حذف کن
      await User.findByIdAndDelete(user._id);
      await cacheDelete(userProfileKey);
      return res.status(500).json({
        message: 'Failed to send verification email. Please try again.'
      });
    }

    // 🔥 تولید توکن موقت و ذخیره در Redis
    const tempToken = jwt.sign(
      {
        userId: user._id.toString(),
        type: 'email_verification',
        temp: true
      },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' }
    );

    // ذخیره توکن موقت در Redis
    const tempTokenKey = `${CACHE_KEYS.TEMP_TOKENS}:${user._id.toString()}`;
    await cacheSet(tempTokenKey, {
      token: tempToken,
      type: 'email_verification',
      createdAt: new Date().toISOString()
    }, 3600); // 1 ساعت

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
    const ip = req.ip || 'unknown';

    logger.debug('Login attempt', { email, rememberMe, ip });

    // 🔥 بررسی بلاک شدن کاربر
    const loginCheck = await handleFailedLogin(email, ip);
    if (loginCheck.blocked) {
      return res.status(429).json({
        message: 'اکانت شما به دلیل تلاش‌های ناموفق متعدد موقتاً مسدود شده است. لطفاً 30 دقیقه دیگر تلاش کنید.'
      });
    }

    // 🔥 بررسی کش برای اطلاعات کاربر
    const userProfileKey = `${CACHE_KEYS.USER_PROFILE}:${email}`;
    let user = await cacheGet(userProfileKey);

    if (!user) {
      // اگر در کش نیست، از دیتابیس بگیر
      const dbUser = await User.findOne({ email });
      if (!dbUser) {
        LoggerService.authLog('unknown', 'login_failed', { reason: 'user_not_found', email });
        logger.warn('Login failed - user not found', { email });
        res.status(400).json({ message: 'Invalid credentials' });
        return;
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

      // ذخیره در کش
      await cacheSet(userProfileKey, user, CACHE_TTL.MEDIUM);
    }

    // 🔥 چک کردن تأیید ایمیل
    if (!user.emailVerified) {
      LoggerService.authLog(user.id, 'login_failed', {
        reason: 'email_not_verified'
      });

      // ارسال مجدد کد تأیید
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const codeExpires = new Date(Date.now() + 10 * 60 * 1000);

      await User.findByIdAndUpdate(user.id, {
        emailVerificationCode: verificationCode,
        emailVerificationCodeExpires: codeExpires,
        emailVerificationSentAt: new Date()
      });

      await EmailService.sendVerificationCode(user.email, verificationCode, user.name);

      // 🔥 آپدیت کش
      await cacheSet(userProfileKey, {
        ...user,
        emailVerificationCode: verificationCode
      }, CACHE_TTL.SHORT);

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
      LoggerService.authLog(user.id, 'login_failed', { reason: 'invalid_password' });
      logger.warn('Login failed - invalid password', { userId: user.id, email });

      // افزایش شمارنده تلاش‌های ناموفق
      await handleFailedLogin(email, ip);

      res.status(400).json({ message: 'invalid-password' });
      return;
    }

    // 🔥 اگر پسورد صحیح است، ریست کردن تلاش‌های ناموفق
    await resetFailedLogin(email, ip);

    // 🔥 فقط اگر ایمیل تأیید شده باشد، توکن اصلی تولید کن
    const expiresIn = rememberMe ? '120d' : '1d';
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET!,
      { expiresIn }
    );

    // آپدیت lastLogin در دیتابیس
    await User.findByIdAndUpdate(user.id, { lastLogin: new Date() });

    // 🔥 آپدیت کش
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

    // 🔥 بررسی کش برای توکن
    const tokenKey = `${CACHE_KEYS.TEMP_TOKENS}:${req.userId}`;
    const cachedToken = await cacheGet(tokenKey);

    if (cachedToken && cachedToken.token === token) {
      logger.debug('Token validated from cache', { userId: req.userId });
      res.json({
        valid: true,
        message: 'Token is valid',
        userId: req.userId,
        fromCache: true
      });
      return;
    }

    jwt.verify(token, process.env.JWT_SECRET!, (err: any, decoded: any) => {
      if (err) {
        logger.warn('Token check failed - invalid token', { error: err.message });
        res.status(401).json({ valid: false, message: 'Invalid token' });
        return;
      }

      // 🔥 ذخیره توکن معتبر در کش
      cacheSet(tokenKey, {
        token: token,
        type: 'access_token',
        validatedAt: new Date().toISOString()
      }, CACHE_TTL.SHORT).catch(() => { });

      logger.debug('Token check successful', { userId: decoded.userId });
      res.json({
        valid: true,
        message: 'Token is valid',
        userId: decoded.userId,
        fromCache: false
      });
    });
  } catch (error) {
    logger.error('Token check error:', error);
    res.status(500).json({ valid: false, message: 'Server error' });
  }
};

// 🆕 تابع برای لاگ‌آوت و حذف کش
export const logout = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.userId;
    const token = req.headers['authorization']?.split(' ')[1];

    if (userId && token) {
      // حذف توکن از کش
      const tokenKey = `${CACHE_KEYS.TEMP_TOKENS}:${userId}`;
      await cacheDelete(tokenKey);

      // حذف پروفایل کاربر از کش (اختیاری - بستگی به استراتژی کش دارد)
      // await cacheDelete(`${CACHE_KEYS.USER_PROFILE}:${userId}`);
    }

    LoggerService.authLog(userId || 'unknown', 'logout_success');

    res.json({
      success: true,
      message: 'Logout successful'
    });

  } catch (error) {
    logger.error('Logout error', { error, userId: req.userId });
    res.status(500).json({
      success: false,
      message: 'Server error during logout'
    });
  }
};

// 🆕 تابع برای دریافت اطلاعات کاربر از کش
export const getUserFromCache = async (userId: string): Promise<any> => {
  try {
    // جستجو در تمام کلیدهای کش برای پیدا کردن کاربر
    const keys = await redisClient.keys(`${CACHE_KEYS.USER_PROFILE}:*`);

    for (const key of keys) {
      const user = await cacheGet(key);
      if (user && user.id === userId) {
        return user;
      }
    }
    return null;
  } catch (error) {
    logger.error('Error getting user from cache', { userId, error });
    return null;
  }
};

// 🆕 تابع برای حذف کاربر از کش
export const invalidateUserAuthCache = async (userId: string, email?: string): Promise<void> => {
  try {
    const keysToDelete = [];

    if (userId) {
      keysToDelete.push(`${CACHE_KEYS.TEMP_TOKENS}:${userId}`);
    }

    if (email) {
      keysToDelete.push(`${CACHE_KEYS.USER_PROFILE}:${email}`);
    }

    // حذف کلیدهای لاگین ناموفق مربوط به این ایمیل
    const failedLoginKeys = await redisClient.keys(`${CACHE_KEYS.LOGIN_ATTEMPTS}:${email}:*`);
    const blockedKeys = await redisClient.keys(`${CACHE_KEYS.BLOCKED_USERS}:${email}:*`);

    keysToDelete.push(...failedLoginKeys, ...blockedKeys);

    if (keysToDelete.length > 0) {
      await redisClient.del(keysToDelete);
      logger.debug('User auth cache invalidated', {
        userId,
        email,
        keysCount: keysToDelete.length
      });
    }
  } catch (error) {
    logger.error('Error invalidating user auth cache', { userId, email, error });
  }
};