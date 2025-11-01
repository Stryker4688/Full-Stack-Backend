// backend/src/routes/auth.ts - به‌روزرسانی شده
import express from 'express';
import { register, login, checkToken } from './authController';
import { googleAuth } from './googleAuthController';
import { setupGooglePassword } from './googlePasswordController';
import {
    sendVerificationEmail,
    verifyEmailCode,
    resendVerification
} from './emailVerificationController';
import {
    rateLimit,
    strictRateLimit,
    rateLimitStatus
} from '../../middlewares/ratelimit';
import { loginValidation, registerValidation } from '../../middlewares/validation';
import { verifyTurnstile } from '../../middlewares/turnstile';
import { authenticateToken } from '../../middlewares/auth';

const router = express.Router();

// 🔐 Public Routes
router.post('/register', registerValidation, verifyTurnstile, rateLimit, register);
router.post('/login', loginValidation, verifyTurnstile, rateLimit, login);
router.post('/google', verifyTurnstile, rateLimit, googleAuth);
router.post('/resend-verification', strictRateLimit, resendVerification);
router.post('/verify-email', strictRateLimit, verifyEmailCode);
router.post('/google/set-password', strictRateLimit, setupGooglePassword);

// 🔒 Protected Routes
router.get('/check-token', authenticateToken, rateLimit, checkToken);
router.post('/send-verification', authenticateToken, rateLimit, sendVerificationEmail);

// 📊 Route برای بررسی وضعیت Rate Limit
router.get('/rate-limit-status', authenticateToken, rateLimitStatus);

export default router;  