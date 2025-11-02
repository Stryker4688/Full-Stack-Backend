// backend/src/routes/auth.ts
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
    getRateLimitStatus
} from '../../middlewares/ratelimit';
import { loginValidation, registerValidation } from '../../middlewares/validation';
import { verifyTurnstile } from '../../middlewares/turnstile';
import { authenticateToken } from '../../middlewares/auth';
import {
    requestPasswordReset,
    verifyResetCode,
    resetPassword
} from './passwordResetController';
import {
    passwordResetRequestValidation,
    verifyResetCodeValidation,
    resetPasswordValidation
} from '../../middlewares/passwordResetValidation';

const router = express.Router();

// 🔐 Public Routes
router.post('/register', registerValidation, verifyTurnstile, rateLimit, register);
router.post('/login', loginValidation, verifyTurnstile, rateLimit, login);
router.post('/google', verifyTurnstile, rateLimit, googleAuth);
router.post('/resend-verification', strictRateLimit, resendVerification);
router.post('/verify-email', strictRateLimit, verifyEmailCode);
router.post('/google/set-password', strictRateLimit, setupGooglePassword);
router.post('/forgot-password', passwordResetRequestValidation, strictRateLimit, requestPasswordReset);
router.post('/verify-reset-code', verifyResetCodeValidation, strictRateLimit, verifyResetCode);
router.post('/reset-password', resetPasswordValidation, strictRateLimit, resetPassword);

// 🔒 Protected Routes
router.get('/check-token', authenticateToken, rateLimit, checkToken);
router.post('/send-verification', authenticateToken, rateLimit, sendVerificationEmail);

// 📊 Rate Limit Status Route - Fixed: Using getRateLimitStatus instead of rateLimitStatus
router.get('/rate-limit-status', authenticateToken, getRateLimitStatus);

export default router;