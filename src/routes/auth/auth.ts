// backend/src/routes/auth.ts - No changes needed
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
    verifyResetCode
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

// 📧 Email authentication routes
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

// 🔐 Google authentication routes
router.post('/google',
    verifyTurnstile,
    rateLimit,
    googleAuth
);

router.post('/google/set-password',
    strictRateLimit,
    setupGooglePassword
);

// 📨 Email verification routes
router.post('/resend-verification',
    strictRateLimit,
    resendVerification
);

router.post('/verify-email',
    strictRateLimit,
    verifyEmailCode
);

// 🔑 Password recovery routes
router.post('/forgot-password',
    strictRateLimit,
    forgotPassword
);

router.post('/reset-password',
    strictRateLimit,
    resetPassword
);

router.post('/verify-reset-code',
    strictRateLimit,
    verifyResetCode
);

// ==================== 🔒 PROTECTED ROUTES ====================

// ✅ Token verification routes
router.get('/check-token',
    authenticateToken,
    rateLimit,
    checkToken
);

router.get('/verify',
    authenticateToken,
    rateLimit,
    verifyUser
);

// 📧 Send verification email (for logged-in users)
router.post('/send-verification',
    authenticateToken,
    rateLimit,
    sendVerificationEmail
);

// 📊 Rate limit status check
router.get('/rate-limit-status',
    authenticateToken,
    rateLimitStatus
);

export default router;