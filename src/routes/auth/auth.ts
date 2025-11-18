// backend/src/routes/auth.ts - اصلاح شده
import express from 'express';
import { register, login, checkToken, verifyUser } from './authController';
import { googleAuth } from './googleAuthController';
import { setupGooglePassword } from './googlePasswordController';
import {
    sendVerificationEmail,
    verifyEmailCode,
    resendVerification
} from './emailVerificationController';
import {
    forgotPassword,
    resetPassword,
    verifyResetCode  // ✅ اصلاح شد
} from './passwordResetController';
import {
    rateLimit,
    strictRateLimit,
    rateLimitStatus
} from '../../middlewares/ratelimit';
import { loginValidation, registerValidation } from '../../middlewares/validation';
import { verifyTurnstile } from '../../middlewares/turnstile';
import { authenticateToken } from '../../middlewares/auth';

const router = express.Router();

// ==================== 🔐 PUBLIC ROUTES ====================

// 📧 احراز هویت ایمیل
router.post('/register',
    registerValidation,
    verifyTurnstile,
    rateLimit,
    register
);

router.post('/login',
    loginValidation,
    verifyTurnstile,
    rateLimit,
    login
);

// 🔐 احراز هویت گوگل
router.post('/google',
    verifyTurnstile,
    rateLimit,
    googleAuth
);

router.post('/google/set-password',
    strictRateLimit,
    setupGooglePassword
);

// 📨 تأیید ایمیل
router.post('/resend-verification',
    strictRateLimit,
    resendVerification
);

router.post('/verify-email',
    strictRateLimit,
    verifyEmailCode
);

// 🔑 بازیابی رمز عبور
router.post('/forgot-password',
    strictRateLimit,
    forgotPassword
);

router.post('/reset-password',
    strictRateLimit,
    resetPassword
);

// 🆕 اضافه کردن route جدید برای verify reset code
router.post('/verify-reset-code',
    strictRateLimit,
    verifyResetCode
);

// ==================== 🔒 PROTECTED ROUTES ====================

// ✅ بررسی توکن
router.get('/check-token',
    authenticateToken,
    rateLimit,
    checkToken
);
router.get('/verify',
    authenticateToken,
    rateLimit,
    verifyUser);
// 📧 ارسال ایمیل تأیید (برای کاربران لاگین کرده)
router.post('/send-verification',
    authenticateToken,
    rateLimit,
    sendVerificationEmail
);

// 📊 بررسی وضعیت Rate Limit
router.get('/rate-limit-status',
    authenticateToken,
    rateLimitStatus
);

export default router;